from werkzeug.utils import secure_filename


def safe_upload(uploaded_name, root):
    filename = secure_filename(uploaded_name)
    return open(root + "/" + filename, "rb")
