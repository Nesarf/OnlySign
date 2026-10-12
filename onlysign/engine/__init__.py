"""The engine: no user interface, no window, every part callable and testable on its own.

The window is the easy half of a signing tool. What is hard -- refusing to sign twice, refusing to
leave a signature that expires with the certificate, pinning the signer, and keeping a record that
an edit cannot quietly change -- lives here, where it can be tested without anyone clicking.
"""
