# Persistence
Persistence using NT kernel calls 

Gains current user security ID (SID) and uses this (\Registry\USER\[SID]\Software\Microsoft\Windows\CurrentVersion\Run) directory to set a new run key for persistence.

NtOpenKey, NtClose, NtSetValueKey

References:
https://social.msdn.microsoft.com/Forums/vstudio/en-US/6b23fff0-773b-4065-bc3f-d88ce6c81eb0/get-user-sid-in-unmanaged-c?forum=vcgeneral
MSDN
