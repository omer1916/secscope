import os

# Qt tests run headless everywhere (CI and local).
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
