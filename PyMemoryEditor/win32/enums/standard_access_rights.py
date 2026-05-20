# -*- coding: utf-8 -*-
from enum import IntFlag


class StandardAccessRightsEnum(IntFlag):
    """
    Standard access rights common to most securable Win32 objects.

    Reference:
      https://learn.microsoft.com/en-us/windows/win32/secauthz/access-mask-format
    """

    # Required to delete the object.
    DELETE = 0x00010000

    # Required to read information in the security descriptor for the object.
    READ_CONTROL = 0x00020000

    # Right to use the object for synchronization.
    SYNCHRONIZE = 0x00100000

    # Required to modify the DACL in the security descriptor for the object.
    WRITE_DAC = 0x00040000

    # Required to change the owner in the security descriptor for the object.
    WRITE_OWNER = 0x00080000
