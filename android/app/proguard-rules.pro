# Keep the diagnostic entry points reachable from the UI.
-keep class ir.hyperion.app.MainActivity { *; }

# Nothing here reflects on model classes, so no further rules are needed. If
# obfuscation is ever enabled, verify the unit tests still pass against the
# cross-language vectors first.
