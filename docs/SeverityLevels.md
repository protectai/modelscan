# modelscan Severity Levels

modelscan classifies potentially malicious code injection attacks in the following four severity levels. 
<br> </br>
- **CRITICAL:** A model file that consists of unsafe operators/globals that can execute code is classified at critical severity. These operators are:
    - exec, eval, runpy, sys, open, breakpoint, os, subprocess, socket, nt, posix
<br> </br>
- **HIGH:** A model file that consists of unsafe operators/globals that can not execute code but can still be exploited is classified at high severity. These operators are:
    - webbrowser, httplib, request.api, Tensorflow ReadFile, Tensorflow WriteFile 
<br> </br>
- **MEDIUM:** A model file that consists of operators/globals that are neither supported by the parent ML library nor are known to modelscan are classified at medium severity.    
    - Keras Lambda layer can also be used for arbitrary code execution. In general, it is not a best practise to add a Lambda layer to a ML model that can get exploited for code injection attacks. 
    - Work in Progress: Custom operators will be classified at medium severity.
<br> </br>
- **LOW:** At the moment no operators/globals are classified at low severity level.