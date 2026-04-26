# Retail Source Boundary Packet: `laser.c`

## Summary
- action: `corridor-packet`
- confidence: `medium`
- suggested path: `dll/CF/laser.c`
- split status: `single-split`
- retail bundles: `4`
- current seed: `0x80209074-0x802090A0` size=`0x2C`
- debug target size: `0x934`
- fit status: `seed-too-small`
- suggested window: `0x80209074-0x802099A8` size=`0x934` delta=`+0x0` xref_coverage=`1/1`
- suggested overlaps: `main/dll/CF/laser_unsupported.c`, `main/dll/CF/laserObj.c`, `main/dll/fire.c`, `main/textblock.c`, ... (+2 more)
- retail labels: `Init`
- xref count: `1`

## Why
- Suggested window overlaps existing split owners `main/dll/CF/laser_unsupported.c`, `main/dll/CF/laserObj.c`, `main/dll/fire.c`, `main/textblock.c`, ... (+2 more); treat this as an ownership packet instead of a clean boundary move.

## EN Xref Functions
- `laser_init@0x80209074-0x802090A0`

## Current Seed Functions
- `laser_init@0x80209074-0x802090A0` size=`0x2C`

## Suggested Inspection Window
- `laser_init@0x80209074-0x802090A0` size=`0x2C`
- `laser_releaseUnsupported@0x802090A0-0x802090A4` size=`0x4`
- `laser_initialiseUnsupported@0x802090A4-0x802090A8` size=`0x4`
- `laserObj_getExtraSize@0x802090A8-0x802090B0` size=`0x8`
- `laserObj_func08@0x802090B0-0x802090B8` size=`0x8`
- `laserObj_free@0x802090B8-0x802090BC` size=`0x4`
- `laserObj_render@0x802090BC-0x802090C0` size=`0x4`
- `laserObj_hitDetect@0x802090C0-0x802090C4` size=`0x4`
- `laserObj_update@0x802090C4-0x8020926C` size=`0x1A8`
- `laserObj_init@0x8020926C-0x80209304` size=`0x98`
- `laserObj_release@0x80209304-0x80209308` size=`0x4`
- `laserObj_initialise@0x80209308-0x8020930C` size=`0x4`
- `fire_updateState@0x8020930C-0x80209700` size=`0x3F4`
- `fireObj_getExtraSize@0x80209700-0x80209708` size=`0x8`
- `fireObj_func08@0x80209708-0x80209710` size=`0x8`
- `fireObj_free@0x80209710-0x80209714` size=`0x4`
- `fireObj_render@0x80209714-0x80209738` size=`0x24`
- `fireObj_hitDetect@0x80209738-0x8020973C` size=`0x4`
- `fireObj_update@0x8020973C-0x80209778` size=`0x3C`
- `fireObj_init@0x80209778-0x80209808` size=`0x90`
- `fireObj_release@0x80209808-0x8020980C` size=`0x4`
- `fireObj_initialise@0x8020980C-0x80209810` size=`0x4`
- `textblockObj_getExtraSize@0x80209810-0x80209818` size=`0x8`
- `textblockObj_func08@0x80209818-0x80209820` size=`0x8`
- `textblockObj_freeUnsupported@0x80209820-0x8020984C` size=`0x2C`
- `textblockObj_render@0x8020984C-0x80209850` size=`0x4`
- `textblockObj_hitDetect@0x80209850-0x80209854` size=`0x4`
- `textblockObj_updateUnsupported@0x80209854-0x80209880` size=`0x2C`
- `textblockObj_initUnsupported@0x80209880-0x802098AC` size=`0x2C`
- `textblockObj_release@0x802098AC-0x802098B0` size=`0x4`
- `textblockObj_initialise@0x802098B0-0x802098B4` size=`0x4`
- `platform1_getExtraSize@0x802098B4-0x802098BC` size=`0x8`
- `platform1_func08@0x802098BC-0x802098C4` size=`0x8`
- `platform1_free@0x802098C4-0x802098C8` size=`0x4`
- `platform1_renderUnsupported@0x802098C8-0x802098F4` size=`0x2C`
- `platform1_hitDetect@0x802098F4-0x802098F8` size=`0x4`
- `platform1_updateUnsupported@0x802098F8-0x80209924` size=`0x2C`
- `platform1_initUnsupported@0x80209924-0x80209950` size=`0x2C`
- `platform1_release@0x80209950-0x80209954` size=`0x4`
- `platform1_initialise@0x80209954-0x80209958` size=`0x4`
- ... (+2 more functions)

## Corridor Context
- previous corridor: `SHroot.c`, `SClevelcontrol.c`, `SClightfoot.c`, `SCchieflightfoot.c`, `SClantern.c`, ... (+106 more)
- next corridor: none
- debug neighbors before: `CFcrystal.c`, `CFBaby.c`
- debug neighbors after: `CFPrisonGuard.c`, `dll_163.c`
- shared island sources: `textblock.c`, `laser.c`
- shared island span: `0x80208FEC-0x802098AC` size=`0x8C0`

## Recommended Next Steps
- Work the whole corridor packet instead of asserting a narrow final boundary immediately.
- Use the listed gap neighbors to decide whether this source should become one file or part of a larger missing cluster.
