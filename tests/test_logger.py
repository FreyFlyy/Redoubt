import logging
import os

from redoubt import logger as logger_mod


def test_logger_lives_under_the_redoubt_namespace_and_does_not_propagate():
    log = logger_mod.get_logger("some.module")
    assert log.name == "redoubt.some.module"
    root = logging.getLogger("redoubt")
    assert root.propagate is False and root.level == logging.INFO


def test_configuration_is_idempotent():
    logger_mod.get_logger("a"); logger_mod.get_logger("b"); logger_mod.get_logger("a")
    ours = [h for h in logging.getLogger("redoubt").handlers      # pytest attaches its own capture handlers
            if isinstance(h, logging.FileHandler) and h.baseFilename == logger_mod.LOG_FILE]
    assert len(ours) == 1


def test_messages_are_written_to_the_log_file_in_the_redirected_home():
    assert logger_mod.LOG_FILE.startswith(os.environ["HOME"])        # tests never touch the real ~/.redoubt
    logger_mod.get_logger("t").warning("canary-message-123")
    for h in logging.getLogger("redoubt").handlers:
        h.flush()
    with open(logger_mod.LOG_FILE, encoding="utf-8") as f:
        content = f.read()
    assert "canary-message-123" in content and "[WARNING] redoubt.t" in content


def test_debug_is_filtered_out():
    logger_mod.get_logger("t").debug("should-not-appear-xyz")
    for h in logging.getLogger("redoubt").handlers:
        h.flush()
    with open(logger_mod.LOG_FILE, encoding="utf-8") as f:
        assert "should-not-appear-xyz" not in f.read()
