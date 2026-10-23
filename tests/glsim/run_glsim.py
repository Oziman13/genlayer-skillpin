"""Start the local GenLayer simulator (glsim) with one patch for tests.

glsim moves the VM clock with sim_setTime, but contracts read gl.message_raw["datetime"], which the
simulator does not refresh. This launcher copies the VM time into it on every refresh, exactly like
the direct-mode tests do by hand. Nothing else is changed.
"""
import sys

from gltest.direct.vm import VMContext

_original = VMContext._refresh_gl_message


def _patched(self):
    _original(self)
    module = sys.modules.get("genlayer.gl")
    stamp = getattr(self, "_datetime", None)
    if module is not None and stamp and getattr(module, "message_raw", None) is not None:
        module.message_raw["datetime"] = stamp


VMContext._refresh_gl_message = _patched

from glsim.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
