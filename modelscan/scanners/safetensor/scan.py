import logging
import json
import struct
import math
from typing import Optional, Dict, Any

from modelscan.scanners.scan import ScanBase, ScanResults
from modelscan.model import Model
from modelscan.settings import SupportedModelFormats
from modelscan.issues import Issue, IssueCode, IssueSeverity, OperatorIssueDetails , FormatIssueDetails
from modelscan.skip import ModelScanSkipped, SkipCategories

logger = logging.getLogger("modelscan")

class SafetensorUnsafeScan(ScanBase):
    HEADER_SIZE_BYTES = 8
    
    FORMAT_SIGNATURES = {
        'pickle': [b'\x80\x03', b'\x80\x04', b'\x80\x05'],
        'torch': b'PK\x03\x04',
    }

    def scan(self, model: Model) -> Optional[ScanResults]:
        if SupportedModelFormats.SAFETENSORS.value not in [
            fmt.value for fmt in model.get_context("formats")
        ]:
            return None
        
        stream = model.get_stream()
        stream.seek(0)
        scan_name = "safetensors"
        issues = []
    
        detected_format = self._detect_file_format(stream)
        if detected_format:
            return self._create_format_mismatch_result(
                f"File claimed to be SafeTensor but appears to be {detected_format}",
                detected_format,
                model,
                IssueSeverity.LOW
            )

        stream.seek(0)
        try:
            header_size_bytes = stream.read(self.HEADER_SIZE_BYTES)
            if len(header_size_bytes) != self.HEADER_SIZE_BYTES:
                return self._create_skip_result(scan_name, "Incomplete or invalid header size bytes", model)

            header_size = struct.unpack("<Q", header_size_bytes)[0]
            if not (0 < header_size <= 100 * 1024 * 1024):
                return self._create_skip_result(scan_name, "Invalid header size", model)

            header_bytes = stream.read(header_size)
            if len(header_bytes) != header_size:
                return self._create_skip_result(scan_name, "Incomplete header content", model)

            try:
                header = json.loads(header_bytes, strict=True)
                if self._has_duplicate_json_keys(header_bytes.decode()):
                    return self._create_skip_result(scan_name, "Duplicate header key", model)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                return self._create_skip_result(scan_name, f"Invalid header: {str(e)}", model)

        except struct.error:
            return self._create_skip_result(scan_name, "Invalid header structure", model)

        total_data_size = stream.seek(0, 2)
        last_end_offset = self.HEADER_SIZE_BYTES + header_size
        for tensor_name, tensor_info in header.items():
            if tensor_name == "__metadata__":
                continue

            if not self._validate_tensor_info(tensor_info, total_data_size):
                issues.append(
                    self._create_issue("invalid_tensor_info", tensor_name, model, IssueSeverity.LOW)
                )

            start, end = tensor_info['data_offsets']
            
            if start < last_end_offset:
                issues.append(
                    self._create_issue("overlapping_tensors", tensor_name, model, IssueSeverity.MEDIUM)
                )

            last_end_offset = max(last_end_offset, end)

            if start == end:
                logger.warning(f"Zero-sized tensor detected: {tensor_name}")

        results = ScanResults(issues, [], [])
        print(results.issues)
        return self.label_results(results)

    def _detect_file_format(self, stream: Any) -> Optional[str]:
        max_sig_length = max(len(sig) for sigs in self.FORMAT_SIGNATURES.values() 
                             for sig in (sigs if isinstance(sigs, list) else [sigs]))
        header = stream.read(max_sig_length)
        
        for format_name, signatures in self.FORMAT_SIGNATURES.items():
            if isinstance(signatures, list):
                if any(header.startswith(sig) for sig in signatures):
                    return format_name
            elif header.startswith(signatures):
                return format_name
        return None

    def _validate_tensor_info(self, tensor_info: Dict[str, Any], total_data_size: int) -> bool:
        required_keys = {'dtype', 'shape', 'data_offsets'}
        if not all(key in tensor_info for key in required_keys):
            print("Missing required keys:", [key for key in required_keys if key not in tensor_info])
            return False

        start, end = tensor_info['data_offsets']
        if not isinstance(start, int) or not isinstance(end, int) or start >= end or end > total_data_size:
            return False

        try:
            num_elements = math.prod(tensor_info['shape'])
            dtype_size = self._dtype_size(tensor_info['dtype'])
            expected_size = num_elements * dtype_size
            actual_size = end - start
            return dtype_size > 0 and expected_size == actual_size
        except (TypeError, ValueError) as e:
            logger.exception("Invalid Type/Value")
            return False

    def _dtype_size(self, dtype: str) -> int:
        dtype_mapping = {
            'f32': 'float32', 'f64': 'float64', 'f16': 'float16',
            'i32': 'int32', 'i64': 'int64', 'i16': 'int16', 'i8': 'int8', 'u8': 'uint8',
            'bf16': 'bfloat16'
        }
        
        normalized_dtype = dtype_mapping.get(dtype.lower(), dtype.lower())
        dtype_sizes = {
            'float32': 4, 'int32': 4, 'int64': 8, 'float64': 8,
            'float16': 2, 'int16': 2, 'int8': 1, 'uint8': 1, 'bfloat16': 2
        }
        
        size = dtype_sizes.get(normalized_dtype, 0)
        
        if size == 0:
            logger.error(f"Unknown dtype: {dtype} (normalized: {normalized_dtype})")
        
        return size

    def _create_format_mismatch_result(self, message: str, detected_format: str, model: Model, severity: IssueSeverity) -> ScanResults:
        issue = Issue(
            code=IssueCode.FORMAT_MISMATCH,
            severity=severity,
            details=FormatIssueDetails(
                module="safetensors",
                detected_format=detected_format,
                source=model.get_source(),
                severity=severity,
            ),
        )
        result = ScanResults([issue], [], [])
        return self.label_results(result)

    def _create_invalid_safetensor_result(self, message: str, model: Model, severity: IssueSeverity) -> ScanResults:
        issue = Issue(
            code=IssueCode.INVALID_HEADER,
            severity=severity,
            details=OperatorIssueDetails(
                module="safetensors",
                operator=message,
                source=model.get_source(),
                severity=severity,
            ),
        )
        result = ScanResults([issue], [], [])
        return self.label_results(result)

    def _create_issue(self, issue_type: str, tensor_name: str, model: Model, severity: IssueSeverity) -> Issue:
        return Issue(
            code=IssueCode.UNSAFE_OPERATOR,
            severity=severity,
            details=OperatorIssueDetails(
                module="safetensors",
                operator=f"{issue_type}: {tensor_name}",
                source=model.get_source(),
                severity=severity,
            ),
        )
    
    def _create_skip_result(self, scan_name: str, msg: str, model: Model) -> ScanResults:
        results = ScanResults(
            [],
            [],
            [
                ModelScanSkipped(
                    scan_name,
                    SkipCategories.HEADER_FORMAT,
                    msg,
                    str(model.get_source()),
                )
            ],
        )
        return self.label_results(results)

    def _has_duplicate_json_keys(self, json_str: str) -> bool:
        seen_keys = set()
        try:
            for key in json.loads(json_str, strict=False):
                if key in seen_keys:
                    return True
                seen_keys.add(key)
        except json.JSONDecodeError:
            return False
        return False

    @staticmethod
    def name() -> str:
        return "safetensors"

    @staticmethod
    def full_name() -> str:
        return "modelscan.scanners.SafetensorUnsafeScan"
