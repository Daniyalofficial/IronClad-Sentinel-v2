"""User-controlled archive/compressed-file locations are filesystem paths."""

from ironclad.scanners.python_flows import scan_python_flows


def _path_lines(tmp_path, source):
    path = tmp_path / "archive_view.py"
    path.write_text(source, encoding="utf-8")
    return [finding.location.start_line for finding in
            scan_python_flows(str(path), path.name)
            if finding.rule_id == "PY-AST-PATH-TRAVERSAL"]


def test_archive_and_compressed_openers_use_tainted_file_path(tmp_path):
    lines = _path_lines(tmp_path,
        "import tarfile, bz2, gzip, zipfile\n"
        "def read(user_input):\n"
        "    tarfile.open(user_input, mode='r:*')\n"
        "    tarfile.TarFile(user_input)\n"
        "    bz2.BZ2File(user_input)\n"
        "    gzip.open(user_input, 'rb')\n"
        "    zipfile.ZipFile(user_input)\n")
    assert lines == [3, 4, 5, 6, 7]


def test_archive_mode_is_not_a_file_path_and_constant_files_are_safe(tmp_path):
    lines = _path_lines(tmp_path,
        "import tarfile, bz2\n"
        "def read(user_input):\n"
        "    tarfile.open('/srv/data.tar', mode=user_input)\n"
        "    bz2.BZ2File('/srv/data.bz2', mode=user_input)\n"
        "    tarfile.open('/srv/data.tar', mode='r:*')\n")
    assert lines == []


def test_named_archive_file_argument_is_checked(tmp_path):
    lines = _path_lines(tmp_path,
        "import zipfile, tarfile\n"
        "def read(user_input):\n"
        "    zipfile.ZipFile(file=user_input)\n"
        "    tarfile.open(name=user_input)\n")
    assert lines == [3, 4]
