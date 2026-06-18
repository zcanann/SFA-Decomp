#ifndef MAIN_DLL_CMENU_ITEM_TABLE_H_
#define MAIN_DLL_CMENU_ITEM_TABLE_H_

#include "types.h"

/*
 * In-game C-menu (radial item ring) item tables.
 *
 * The C-menu has three sections, selected by gCMenuCurSection (mi):
 *   mi 0 -> gCMenuCollectableItems  (collectable / quest items)
 *   mi 1 -> gCMenuStaffAbilities        (staff upgrades/abilities)
 *   mi 2 -> gCMenuTrickyAbilities       (Tricky commands; built via the useTricky path)
 * gCMenuSections[mi] points at the section's CMenuItemDef[] (see CMenuSection).
 *
 * cMenuSetItems() rebuilds the visible list every frame: for each entry whose
 * ownedGameBit is currently set (GameBit_Get != 0) and whose usedGameBit is
 * clear, it appends the entry to the CMenuHud arrays and loads iconTextureId.
 * The on-screen item set therefore mirrors live save state - picking an item
 * up sets its ownedGameBit; using/consuming it sets usedGameBit.
 *
 * Layout, field meanings and the item map below were confirmed live via the
 * Dolphin MCP against retail save data (give-item / icon-swap experiments).
 * See docs/live_debugging_workflow.md.
 */
typedef struct CMenuItemDef
{
    s16 ownedGameBit;  /* +0x0  owned/visible while GameBit_Get(this) != 0 */
    s16 usedGameBit;   /* +0x2  consumed/used gate; entry hidden while set (-1 = none) */
    s16 activeGameBit; /* +0x4  "currently in use" gate (-1 = none) */
    s16 iconTextureId; /* +0x6  HUD icon texture id (drives the on-screen art) */
    s16 unk8;          /* +0x8  -1 in every shipped entry */
    s16 unkA;          /* +0xA  per-entry value, purpose TBD */
    s16 nameTextId;    /* +0xC  gametext id for the "<verb> <noun>" label */
    u8  unkE;          /* +0xE  0xff in every shipped entry */
    u8  unkF;          /* +0xF  0x01 in every shipped entry */
} CMenuItemDef; /* sizeof 0x10 */

typedef struct CMenuSection
{
    CMenuItemDef* items; /* +0x0  item table, terminated by an ownedGameBit == -1 entry */
    s16 cursor;          /* +0x4  remembered selection index for this section */
    s16 unk6;
    int flags;           /* +0x8 */
    int unkC;
} CMenuSection; /* sizeof 0x10 */

/*
 * Collectable item name-text ids (gametext). Several quest items reuse one
 * name+icon across many ownedGameBits (one bit per door/location/instance).
 *
 *  text   item ("<verb> <noun>")    icon     ownedGameBit(s)        notes
 *  ----   ---------------------     ----     ---------------        -----
 *  0x404  (cut / glitched)          0x245    0xc7, 0x8a0            broken UI art
 *  0x405  Use Prison Key            0x175    0x44                   Dark Ice Mines
 *  0x406  Use Power Key             0x176    0x60                   CloudRunner Fortress
 *  0x409  Place Crystal             0x180-2  0x51, 0x52, 0x53       CRF power room (x3)
 *  0x40b  Use Shackle Key           0x175    0x2b                   shares Prison icon
 *  0x40c  Use Alpine Root           0x1a3    0x170, 0x576           feed mammoth (x2)
 *  0x40d  Place Cog                 0x479    0x17b,0x17e,0x17f,0x180 DIM bridge
 *  0x411  Use SpellStone            0xc1c/d  0x2e8,0x83a,0x7bd,0x7bf,
 *                                            0x123,0x22b,0x83b,0x83c active-gated by 0xcbc
 *  0x415  Blow Horn                 0xc8a    0x1ee
 *  0x416  Use Key                   0x568    0x336, 0x611           Moon Mountain Pass door
 *  0x417  Use Lantern               0xc06    0x13e                  shop; consumes a firefly
 *  0x418  Plant MoonSeed            0x40d    0x86a                  MMP wall-climb
 *  0x419  Blow Flute                0xc87    0x953                  CRF queen's children
 *  0x41b  Feed to Tricky            0xc89    0xc1                   blue grubtub
 *  0x41c  Plant Bomb Spore          0xc93    0x66c
 *  0x41d  Feed to Queen             0x497    0x66d                  white grubtub; cure Queen
 *  0x41e  Use Gold Key              0x41b    0x1f1, 0x91c           (0x91c = the picked-up key)
 *  0x41f  Use Silver Key            0x41c    0x1f3, 0x241, 0x282    bugged texture
 *  0x420  Use Silver Tooth          0x52b    0x81d                  Walled City (King RedEye)
 *  0x421  Use Gold Tooth            0x52a    0x81e                  Walled City
 *  0x422  Use Sun Stone             0x3a8    0x201                  Walled City (Krazoa)
 *  0x423  Use Moon Stone            0x3d6    0x264                  Walled City
 *  0x424  Place Fire Weed           0xc96    0x194                  Thorntail beacons
 *  0x425  Place Fire Gem            0xc29    0xa9                   real entry (icon 0xc29)
 *  0x425  Place Fire Gem            0x175    0x2d6                  bugged dup (key icon)
 *  0x426  Use Fuel Cells            0xc19    0x3f5                  dungeon flight
 *  0x469  Give Scarabs              0xc88    0x1be                  currency
 *  0x46a  Give Gift                 0xc1f    0x1a2                  golden acorn -> SnowHorn dino
 *  0x46c  Give Gold                 0xbfd    0xaf7                  Cape Claw (x4 gold bars)
 *  0x47e  Give Gift                 0xc9c    0xc7c                  rock candy -> Warpstone
 *  0x45b  PDA On/Off                0xc1b    0xc8d                  toggles the PDA UI
 *  0x544  Place Block               0xc15-7  0xc25, 0xc26, 0xc27   Lightfoot (x3 shapes)
 *  0x549  Drop Token                0xc9e    0xddc-0xde3           cheat tokens, Warpstone maze (x8)
 *  0x4c3  Use Gate Key              0xc6f    0xd20                  SnowHorn Wastes
 */

/*
 * Tricky abilities (gCMenuTrickyAbilities, the useTricky == 1 section).
 *
 * Unlike collectables, the tricky table is NOT gated by GameBits: ownedGameBit
 * is instead a single ABILITY BIT tested against gTrickyHudActionMask (shown)
 * and gTrickyHudItemMask (usable). Both masks are recomputed every frame by
 * drawTrickyHudOverlay() from the Tricky object's vtable (+0x20 = action mask,
 * +0x24 = usable mask); with no Tricky companion both are forced to 0.
 *
 *  bit    text   ability        icon     notes
 *  ----   ----   -------        ----     -----
 *  0x01   0x3f7  Call Tricky    0xc81    whistle; Tricky comes to you
 *  0x20   0x3f8  Throw Ball     0xc84    ball bought from the shop
 *  0x02   0x3f9  Find Secret    0xc82    Tricky digs up buried items
 *  0x10   0x3fa  Use Flame      0xc83    fire breath (burns MoonSeeds, etc.)
 *  0x08   0x3fc  Tricky Stay!   0xc85    hold position (pressure plates)
 */

/*
 * Staff abilities (gCMenuStaffAbilities, the mi == 1 section). GameBit-gated
 * like collectables (useTricky == 0): ownedGameBit unlocks the ability,
 * usedGameBit hides it. Ground Quake (0x107) is gated by 0xc55, which is also
 * the ownedGameBit of Super Quake - unlocking the upgrade swaps the entry.
 *
 *  text   ability             icon   ownedGameBit  notes
 *  ----   -------             ----   ------------  -----
 *  0x3fd  Fire Blaster        0xc7a  0x2d
 *  0x3fe  Freeze Blast        0xc7b  0x5ce         freezes / puts out fires
 *  0x3ff  SharpClaw Disguise  0xc7c  0x40          enemies stop targeting you
 *  0x400  Ground Quake        0xc08  0x107         hidden once 0xc55 (Super Quake) is set
 *  0x56b  Super Quake         0xc1a  0xc55         upgrade; replaces Ground Quake
 *  0x401  Open Portal         0xc7d  0x5bd         opens the large square doors
 *  0x402  Staff Booster       0xc07  0x957         uses boost pads to reach high ledges
 */

#endif /* MAIN_DLL_CMENU_ITEM_TABLE_H_ */
