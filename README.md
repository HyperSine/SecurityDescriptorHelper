# SecurityDescriptor Helper

## 1. sddl-display

### 1.1 Compile

```console
$ git clone https://github.com/DoubleLabyrinth/SecurityDescriptorHelper.git
$ cd SecurityDescriptorHelper
$ msbuild SecurityDescriptorHelper.sln /target:sddl-display /p:Configuration=Release /p:Platform=x64    # or `x86` if you like
```

Then you will see `sddl-display.exe` in `bin\x64-Release\` folder.

### 1.2 Usage

``` console
$ sddl-display.exe <SDDL string>
```

### 1.3 Example

```console
$ sddl-display D:P(A;;GA;;;SY)
->Revision: 0x1
->Sbz1    : 0x0
->Control : 0x9004
          : (0x0004) SE_DACL_PRESENT
          : (0x1000) SE_DACL_PROTECTED
          : (0x8000) SE_SELF_RELATIVE
->Owner   :
->Group   :
->Dacl    : ->AclRevision: 0x2
->Dacl    : ->Sbz1       : 0x0
->Dacl    : ->AclSize    : 0x1c
->Dacl    : ->AceCount   : 0x1
->Dacl    : ->Sbz2       : 0x0
->Dacl    : ->Ace[0]: ->AceType : 0x00 (ACCESS_ALLOWED_ACE_TYPE)
->Dacl    : ->Ace[0]: ->AceFlags: 0x00
->Dacl    : ->Ace[0]: ->AceSize : 0x14
->Dacl    : ->Ace[0]: ->Mask    : 0x10000000
->Dacl    : ->Ace[0]: ->SID     : S-1-5-18 (NT AUTHORITY\SYSTEM)

->Sacl    :  is NULL
```

