#ifndef _MAIN_MAPIDS_H_
#define _MAIN_MAPIDS_H_

#include "types.h"
#include "main/map_romlist_page.h"

#define NUM_LINK_MAPS 9

/* Map ID space (index into sMapFileNameTable / MAPINFO.bin), 0x00-0x74.
   Trailing comment is the MAPINFO.bin debug name; "unused" = wiki's Z-prefixed placeholder maps. */
typedef enum MapId
{
    MAP_ID_FRONTEND        = 0x00, /* Ship Battle - start of game */
    MAP_ID_FRONTEND2       = 0x01, /* unused; only map with T=3 */
    MAP_ID_DRAGROCK        = 0x02, /* Dragon Rock - Top */
    MAP_ID_KRAZOAPALACE    = 0x03, /* unused */
    MAP_ID_TEMPLE          = 0x04, /* Volcano Force Point */
    MAP_ID_HIGHTOP         = 0x05, /* unused */
    MAP_ID_DISCOVERY       = 0x06, /* unused */
    MAP_ID_HOLLOW          = 0x07, /* ThornTail Hollow */
    MAP_ID_HOLLOW2         = 0x08, /* ThornTail Hollow - Undergro */
    MAP_ID_MAZECAVE        = 0x09,
    MAP_ID_WASTES          = 0x0A, /* SnowHorn Wastes */
    MAP_ID_WARLOCK         = 0x0B, /* Krazoa Palace */
    MAP_ID_FORTRESS        = 0x0C, /* CloudRunner Fortress */
    MAP_ID_WALLCITY        = 0x0D, /* Walled City */
    MAP_ID_SWAPCIRCLE      = 0x0E, /* LightFoot Village */
    MAP_ID_CLOUDTREASURE   = 0x0F, /* unused */
    MAP_ID_CLOUDDUNGEON    = 0x10,
    MAP_ID_CLOUDTRAP       = 0x11, /* unused */
    MAP_ID_MOONPASS        = 0x12,
    MAP_ID_SNOWMINES       = 0x13, /* DarkIce Mines - Top */
    MAP_ID_KRASHRIN2       = 0x14, /* unused */
    MAP_ID_KRAZTEST        = 0x15, /* Ocean Force Point - Bottom */
    MAP_ID_KRAZCHAMBER     = 0x16, /* unused */
    MAP_ID_NEWICEMOUNT     = 0x17, /* Ice Mountain */
    MAP_ID_NEWICEMOUNT2    = 0x18, /* unused */
    MAP_ID_NEWICEMOUNT3    = 0x19, /* unused */
    MAP_ID_ANIMTEST        = 0x1A, /* default map for invalid IDs */
    MAP_ID_SNOWMINES2      = 0x1B, /* DarkIce Mines - Bottom */
    MAP_ID_SNOWMINES3      = 0x1C, /* BOSS DarkIce */
    MAP_ID_CAPECLAW        = 0x1D,
    MAP_ID_INSIDEGAL       = 0x1E, /* unused */
    MAP_ID_DFSHRINE        = 0x1F, /* Test Of Combat */
    MAP_ID_MMSHRINE        = 0x20, /* Test Of Fear */
    MAP_ID_ECSHRINE        = 0x21, /* Test Of Skill */
    MAP_ID_GPSHRINE        = 0x22, /* Test Of Knowledge */
    MAP_ID_DIAMONDBAY      = 0x23, /* unused */
    MAP_ID_EARTHWALKER     = 0x24, /* unused */
    MAP_ID_WILLOW          = 0x25, /* unused */
    MAP_ID_ARWING          = 0x26, /* ArWing Level - Andross; T=4 */
    MAP_ID_DBSHRINE        = 0x27, /* Test Of Strength */
    MAP_ID_NWSHRINE        = 0x28, /* BOSS Scales */
    MAP_ID_CCSHRINE        = 0x29, /* World Map; T=4 */
    MAP_ID_WGSHRINE        = 0x2A, /* unused */
    MAP_ID_CLOUDRACE       = 0x2B,
    MAP_ID_FINALBOSS       = 0x2C, /* BOSS Drakor */
    MAP_ID_WMINSERT        = 0x2D, /* unused */
    MAP_ID_SNOWMINES4      = 0x2E, /* unused */
    MAP_ID_SNOWMINES5      = 0x2F, /* unused */
    MAP_ID_TREXBOSS        = 0x30, /* BOSS TRex */
    MAP_ID_MIKELAVA        = 0x31, /* unused */
    MAP_ID_DFPTOP          = 0x32, /* Ocean Force Point - Top */
    MAP_ID_SWAPSTORE       = 0x33, /* Shop */
    MAP_ID_DRAGBOT         = 0x34, /* Dragon Rock - Bottom */
    MAP_ID_KAMDRAG         = 0x35, /* unused */
    MAP_ID_MAGICAVE        = 0x36, /* Magic Cave - Small/Big */
    MAP_ID_DUSTER          = 0x37, /* unused */
    MAP_ID_LINKB           = 0x38, /* LinkB - Ice2Wastes */
    MAP_ID_CLOUDJOIN       = 0x39, /* unused */
    MAP_ID_ARWINGTOPLANET  = 0x3A, /* T=4 */
    MAP_ID_ARWINGDARKICE   = 0x3B, /* T=4 */
    MAP_ID_ARWINGCLOUD     = 0x3C, /* T=4 */
    MAP_ID_ARWINGCITY      = 0x3D, /* T=4 */
    MAP_ID_ARWINGDRAGON    = 0x3E, /* T=4 */
    MAP_ID_GAMEFRONT       = 0x3F, /* title screen; T=4 */
    MAP_ID_LINKLEVEL       = 0x40, /* unused */
    MAP_ID_GREATFOX        = 0x41,
    MAP_ID_LINKA           = 0x42, /* Warpstone to Others */
    MAP_ID_LINKC           = 0x43, /* Wastes to Hollow */
    MAP_ID_LINKD           = 0x44, /* Darkmines top to bottom */
    MAP_ID_LINKE           = 0x45, /* hollow to moon pass */
    MAP_ID_LINKF           = 0x46, /* moonpass to volcano */
    MAP_ID_LINKG           = 0x47, /* hollow to lightfoot */
    MAP_ID_LINKH           = 0x48, /* lightfoot to capeclaw */
    //note out of order names here
    MAP_ID_LINKJ           = 0x49, /* capeclaw to ocean force point */
    MAP_ID_LINKI           = 0x4A, /* CloudRunner to Race */

    /* 0x4B+: no map directory - ObjType-only prefab-object slots, all T=1 */
    MAP_ID_DFPODIUM        = 0x4B,
    MAP_ID_DFCRADLE        = 0x4C,
    MAP_ID_DFCAVEHATCH1    = 0x4D,
    MAP_ID_DFCAVEHATCH2    = 0x4E,
    MAP_ID_SCSTATUE        = 0x4F,
    MAP_ID_GALLEONSHIP     = 0x50, /* ObjType SB_Galleon */
    MAP_ID_CFGALLEON       = 0x51, /* ObjType CFScalesGal */
    MAP_ID_CFGANGPLANK     = 0x52,
    MAP_ID_NWTREEBRIDGE    = 0x53,
    MAP_ID_CFDUNGEONBLOCK  = 0x54, /* ObjType CFDungeonBl */
    MAP_ID_CLOUDRUNNERMAP  = 0x55, /* ObjType SB_Cloudrun */
    MAP_ID_CCBRIDGE        = 0x56, /* ObjType CCBridge */
    MAP_ID_CFCOLUMN        = 0x57, /* ObjType CF_BobbingC */
    MAP_ID_NWBOULDER       = 0x58,
    MAP_ID_CFPRISONDOOR    = 0x59, /* ObjType CFPrisonDoo */
    MAP_ID_CFPRISONCAGE    = 0x5A, /* ObjType CFPrisonCag */
    MAP_ID_NWTREEBRIDGE2   = 0x5B, /* ObjType NW_treebrid */
    MAP_ID_DIM2ICEBLOCK1   = 0x5C, /* ObjType DIM2IcePlat */
    MAP_ID_DIMPUSHBLOCK    = 0x5D, /* ObjType DIMWoodDoor */
    MAP_ID_DIM2ICEBLOCK2   = 0x5E, /* ObjType DIM2IcePlat */
    MAP_ID_DIMHORNPLINTH   = 0x5F,
    MAP_ID_NWSHCOLPUSH     = 0x60,
    MAP_ID_DIM2LIFT        = 0x61,
    MAP_ID_DIM2ICEFLOE     = 0x62, /* ObjType DIM2IceFloe */
    MAP_ID_DIM2ICEFLOE1    = 0x63, /* ObjType DIM2IceFloe */
    MAP_ID_DIM2ICEFLOE2    = 0x64, /* ObjType DIM2IceFloe */
    MAP_ID_CFLIFTPLAT      = 0x65,
    MAP_ID_IMSPACECRAFT    = 0x66, /* ObjType IMAnimSpace */
    MAP_ID_DIMBOSSGUT      = 0x67, /* ObjType DIM_BossGut */
    MAP_ID_WMCOLRISE       = 0x68, /* ObjType WM_colrise */
    MAP_ID_VFPSLIDE1       = 0x69, /* ObjType VFP_Platfor */
    MAP_ID_VFPSLIDE2       = 0x6A, /* ObjType VFPLavaBloc */
    MAP_ID_DRPUSHCART      = 0x6B, /* ObjType DR_PushCart */
    MAP_ID_DRLIFTPLAT      = 0x6C, /* ObjType DR_Platform */
    MAP_ID_DIM2STONEPILLAR = 0x6D, /* ObjType DIM2StonePi */
    MAP_ID_BOSSDRAKORFLATR = 0x6E, /* ObjType WCPushBlock */
    MAP_ID_WCBOUNCYCRATE   = 0x6F, /* ObjType WCBouncyCra */
    MAP_ID_WCPUSHBLOCK     = 0x70, /* ObjType WCPushBlock */
    MAP_ID_WCTEMPLELIFT    = 0x71, /* ObjType WCMoonTempl */
    MAP_ID_KAMCOLUMN       = 0x72,
    MAP_ID_DBSTEPSTONE     = 0x73,
    MAP_ID_VFPPUSHBLOCK    = 0x74, /* ObjType VFP_Bobbing */
} MapId;

typedef enum MapDirId {
    MAPDIR_ID_ARWING         = 0x03,
    MAPDIR_ID_DRAGROCK       = 0x04,
    MAPDIR_ID_ANIMTEST       = 0x05,
    MAPDIR_ID_DFPTOP         = 0x06,
    MAPDIR_ID_VOLCANO        = 0x07,
    MAPDIR_ID_MAZECAVE       = 0x09,
    MAPDIR_ID_DRAGROCKBOT    = 0x0A,
    MAPDIR_ID_SWAPHOL        = 0x0C,
    MAPDIR_ID_SHIPBATTLE     = 0x0D,
    MAPDIR_ID_NWASTES        = 0x0E,
    MAPDIR_ID_WARLOCK        = 0x0F,
    MAPDIR_ID_SHOP           = 0x10,
    MAPDIR_ID_CRFORT         = 0x12,
    MAPDIR_ID_SWAPHOLBOT     = 0x13,
    MAPDIR_ID_WALLCITY       = 0x14,
    MAPDIR_ID_LIGHTFOOT      = 0x15,
    MAPDIR_ID_CLOUDTREASURE  = 0x16,
    MAPDIR_ID_CLOUDDUNGEON   = 0x18,
    MAPDIR_ID_MMPASS         = 0x19,
    MAPDIR_ID_DARKICEMINES   = 0x1A,
    MAPDIR_ID_DESERT         = 0x1C,
    MAPDIR_ID_ICEMOUNTAIN    = 0x1E,
    MAPDIR_ID_ANIMTEST_1F    = 0x1F,
    MAPDIR_ID_ANIMTEST_20    = 0x20,
    MAPDIR_ID_DARKICEMINES2  = 0x22,
    MAPDIR_ID_BOSSGALDON     = 0x23,
    MAPDIR_ID_INSIDEGAL      = 0x25,
    MAPDIR_ID_MAGICCAVE      = 0x26,
    MAPDIR_ID_DFSHRINE       = 0x27,
    MAPDIR_ID_MMSHRINE       = 0x28,
    MAPDIR_ID_ECSHRINE       = 0x29,
    MAPDIR_ID_GPSHRINE       = 0x2A,
    MAPDIR_ID_DBSHRINE       = 0x2B,
    MAPDIR_ID_NWSHRINE       = 0x2C,
    MAPDIR_ID_WORLDMAP       = 0x2D,
    MAPDIR_ID_CAPECLAW       = 0x2F,
    MAPDIR_ID_DBAY           = 0x30,
    MAPDIR_ID_CLOUDRACE      = 0x32,
    MAPDIR_ID_BOSSDRAKOR     = 0x33,
    MAPDIR_ID_BOSSTREX       = 0x35,
    MAPDIR_ID_LINKB          = 0x36,
    MAPDIR_ID_CLOUDJOIN      = 0x37,
    MAPDIR_ID_ARWINGTOPLANET = 0x38,
    MAPDIR_ID_ARWINGDARKICE  = 0x39,
    MAPDIR_ID_ARWINGCLOUD    = 0x3A,
    MAPDIR_ID_ARWINGCITY     = 0x3B,
    MAPDIR_ID_ARWINGDRAGON   = 0x3C,
    MAPDIR_ID_GAMEFRONT      = 0x3D,
    MAPDIR_ID_LINKLEVEL      = 0x3E,
    MAPDIR_ID_GREATFOX       = 0x3F,
    MAPDIR_ID_LINKA          = 0x40,
    MAPDIR_ID_LINKC          = 0x41,
    MAPDIR_ID_LINKD          = 0x42,
    MAPDIR_ID_LINKE          = 0x43,
    MAPDIR_ID_LINKF          = 0x44,
    MAPDIR_ID_LINKG          = 0x45,
    MAPDIR_ID_LINKH          = 0x46,
    MAPDIR_ID_LINKJ          = 0x47,
    MAPDIR_ID_LINKI          = 0x48,
} MapDirId;

#define ROM_LIST_PAGE_COUNT 120
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern MapRomListPage* gLoadedRomListPages[ROM_LIST_PAGE_COUNT];

typedef MapRomListPage MapRomList;

typedef struct MapCellEntry {
    union {
        struct {
            s16 mapId;
            s16 adjacentMapId1;
            s16 adjacentMapId2;
        };
        s16 mapIds[3];
    };
    s16 blockId;
    s8 cellIndex;
    s8 romListIndex;
    s16 unkA;
} MapCellEntry;

STATIC_ASSERT(sizeof(MapCellEntry) == 0xC);
STATIC_ASSERT(offsetof(MapCellEntry, mapIds) == 0x00);
STATIC_ASSERT(sizeof(((MapCellEntry*)0)->mapIds) == 0x06);
STATIC_ASSERT(offsetof(MapCellEntry, mapId) == 0x00);
STATIC_ASSERT(offsetof(MapCellEntry, adjacentMapId1) == 0x02);
STATIC_ASSERT(offsetof(MapCellEntry, adjacentMapId2) == 0x04);
STATIC_ASSERT(offsetof(MapCellEntry, romListIndex) == 0x09);

/* MAPINFO.bin per-record map type (curMapType / getCurMapType()). */
typedef enum MapType {
    MAPTYPE_NORMAL = 0,        /* normal outdoor map */
    MAPTYPE_SUBMAP = 1,        /* normal submap (dungeon/indoor) */
    MAPTYPE_UNLOAD_UNUSED = 2, /* unused: unloads all objects immediately on load */
    MAPTYPE_SUBMAP_UNUSED = 3, /* unused: same as MAPTYPE_UNLOAD_UNUSED; only frontend2 has this */
    MAPTYPE_NO_HUD = 4,        /* hides PDA HUD; title screen + Arwing maps; no player object spawned */
} MapType;

#endif //_MAIN_MAPIDS_H_
