title: Use of CLIP
id: ddeff553-5233-4ae9-bbab-d64d2bd634be
status: experimental
author: frack113
date: 2021/07/27
description: Adversaries may collect data stored in the clipboard from users copying information within or between applications.
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/clip
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1115/T1115.md
tags:
    - attack.collection
    - attack.t1115
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\clip.exe'
        - OriginalFileName: clip.exe
    condition: selection
falsepositives:
    - Unknown
level: low