import pentaster

def test_package_has_version():
    assert isinstance(pentaster.__version__, str)
    assert pentaster.__version__
