#ifndef MAIN_GAMEBITS_H_
#define MAIN_GAMEBITS_H_

#include "global.h"

u32 mainGetBit(int eventId);
void mainSetBits(int eventId, int value);

/*
 * GameBitId - symbolic ids for the game's persistent quest/story/event flags,
 * the integer `eventId` passed to mainGetBit / mainSetBits / gameBitIncrement.
 *
 * Most bits are addressed by raw id from level/placement data, so their meaning
 * lives in the data, not the code; the codebase therefore still uses bare
 * literals at most call sites. ONLY add an entry here once the bit's meaning is
 * actually established (traced to its setter, or confirmed live) - an
 * unverified GAMEBIT_0xNNN is no more useful than the literal. Leave unknown
 * ids as hex and grow this enum as bits are identified.
 */
enum GameBitId {
    /*
     * One-shot latch for the Krazoa Spirit 1 (K1) shrine door intro dialogue. Both the
     * WCEarthWalker door NPC (dll_028A, encounterType 8) and dll_01FB run the
     * identical "if unset: run object sequence 4, disable the A-button, set the
     * bit" path, so talking to either plays the cutscene exactly once. Once set,
     * the Krazoa Shrine door stays unlocked. Live-verified in Dolphin: talking
     * to the door EarthWalker flips this 0 -> 1 and the shrine door opens.
     */
    GAMEBIT_K1_SHRINE_DOOR_DIALOGUE_DONE = 0x9ad,

    /*
     * Entrance-intro signal for the K1 (ECSH) Krazoa Shrine. The shrine-entrance
     * trigger volume sets this (via objInterpretSeq, dll_0126) when the player
     * crosses it; ecsh_shrine_update polls it once and, the first frame it sees
     * it set, plays the "You have found your way into a KRAZOA SHRINE..."
     * NPC dialogue (0x285), latching EcshShrineState.introTextLatch so it never
     * repeats. NOT a "seen" gate - live-verified in Dolphin: setting this bit
     * makes the shrine play the intro on the spot (it is the trigger, and the
     * one-shot behaviour lives in the shrine's latch, not in this bit).
     */
    GAMEBIT_K1_SHRINE_INTRO_TEXT_TRIGGER = 0x58b,

    /*
     * One-shot latch set the first time the player walks within
     * gSpiritDoorLockApproachRange of a SpiritDoorLock (dll_0167); gates the
     * lock's intro text (object sequence 0) so it plays once, game-wide. NOT
     * Krazoa-spirit related: a SpiritDoorLock is a life-force GATE lock that
     * holds a gate shut until enough of the area's enemies are defeated, and
     * appears in normal levels too (not just shrines). Live-verified: walking
     * up to the door flips this 0 -> 1 (region 2, bit start 36) and runs the
     * intro sequence; set by SpiritDoorLock_update. (Was the per-DLL define
     * SPIRITDOORLOCK_GAMEBIT_PLAYER_APPROACHED in IMspacecraft.h.) This bit is
     * actually GENERIC: SpiritDoorLock_update (dll_0167) uses this one
     * hard-coded id for ANY SpiritDoorLock, so it is a global "first
     * spirit-door-lock approached -> play intro once" latch. In practice it
     * only ever flips at this K1 instance because that is the FIRST
     * spirit-door-lock in the game and the linear critical path forces the
     * player through it, which is why the K1 prefix is acceptable here.
     */
    GAMEBIT_K1_SPIRITDOORLOCK_PLAYER_APPROACHED = 0xab9,

    /*
     * The K1 life-force gate's "monster defeated" bit. Unlike the approach
     * latch above this is NOT hard-coded - it is level data, read as BOTH the
     * gate enemy's deathGamebit (placement +0x18, BADDIE_PLACEMENT_DEATH_GAMEBIT)
     * AND the orbiting skull's (SpiritDoorSpirit, dll_0157) gateGameBit
     * (placement +0x1E); the level designer wires them to the same id so killing
     * the monster dismisses its skull. Set on defeat by tricky_handleDefeat ->
     * gameBitIncrement (skipped when the baddie is BADDIE_CONTROL_SEQUENCE_DRIVEN).
     * Live-verified: killing the monster flips this 0 -> 1 (region 2, start 2560)
     * via the caught mainSetBits; it also gates the enemy's respawn (clearing it
     * respawns the monster and re-shows the skull). Per-placement - this is the
     * K1 (first, mandatory) gate's value; other gates carry their own.
     */
    GAMEBIT_K1_GATE_MONSTER_DEFEATED = 0xecb,

    /*
     * The K1 life-force gate's "seal broken / gate open" latch - the
     * SpiritDoorLock's doneGameBit (placement +0x1E). SpiritDoorLock_update sets
     * it the frame the orbiting skull ring empties (all the gate's monsters
     * defeated), after which the lock disables and the gate stays open. Also
     * level data, not hard-coded. Live-verified: appears at region 2, start 1341
     * when the ring empties; clearing it re-arms the lock (its activeGameBit is
     * 0x95, a hard-coded always-1 id, so the lock is always armed) and re-forms
     * the seal. Per-placement - the K1 gate's value.
     */
    GAMEBIT_K1_LIFEFORCE_GATE_OPENED = 0xa5e,

    /*
     * Set when the player collects the K1 Krazoa Spirit at its shrine (the ECSH
     * shrine, dll_018F, anim-event 7 - the same event that calls
     * objSetAnimStateFlags(player, 0x08, 1) to set the spirit bit in playerStatus). It is
     * one of the three guard bits (with 0x316 and 0x511) that disable the K1
     * Krazoa Shrine return transporter pad (dll_012C destinationId 0x43F83 ->
     * map 0x21): once the spirit is taken, the pad locks out. Live-verified that
     * setting this disable path kills the pad's A-prompt.
     */
    GAMEBIT_K1_SPIRIT_COLLECTED = 0xBA8,

    /*
     * K1 Krazoa Spirit DEPOSITED at its place in Krazoa Palace (on Warlock
     * Mountain - the 'warlock' map, hence the WM dll prefix). Set when the
     * deposit sequence completes at the wmspiritplace pedestal (DLL 0x20C): it
     * is that pedestal's placement sequenceGameBit (+0x1E), written via
     * mainSetBits(state->sequenceGameBit) in WM_spiritplace_update - i.e.
     * DATA-DRIVEN, so no mainSetBits(0x316) literal exists (which is why a code
     * grep finds no setter; traced live in Dolphin by catching the write, with
     * r28 == 0x316*4 and the wmspiritplace object in r27). Read as a code
     * literal by dll_012C_transporter.c - one of the three 0xBA8/0x316/0x511
     * guard bits that lock out the K1 return pad once you progress.
     */
    GAMEBIT_K1_SPIRIT_DEPOSITED = 0x316,

    /*
     * World map / Arwing flight-select is available. worldplanet_init force-sets
     * this (mainSetBits(0xA63, 1)) every time the map opens, and
     * gWorldPlanetGameBitTable reuses it as planet slot 2's "unlock" entry - which
     * is why Dinosaur Planet is always flyable and is the default selection. Its
     * FIRST set is the first world-map open, right after the K1 Krazoa Spirit is
     * deposited (when the player first gains Arwing / world-map access), hence its
     * position here in story order. Named WORLDPLANET_GAMEBIT_WORLD_MAP_OPEN in
     * worldplanet.h. Live-verified: set at the post-prologue map (unlockedPlanetMask
     * bit 2), Dinosaur Planet selectable.
     */
    GAMEBIT_WORLDMAP_OPEN = 0xA63,

    /*
     * Arwing on-rails flight ring-gate result - the first gamebits set after the
     * world map opens (the intro flight to Dinosaur Planet). At the end of a
     * flight the ring-choice trigger (arwlevelcon, dll_02A1) compares collected
     * vs required rings and sets one; the pass/fail follow-up sequence and
     * arwarwing_update (polling mainGetBit(0x9d8)) branch on it. Transient -
     * both are reset to 0 at each flight start (arwlevelcon_init / seq start).
     */
    GAMEBIT_ARWING_FLIGHT_RINGS_PASSED = 0x9D8, /* collected >= required (success) */
    GAMEBIT_ARWING_FLIGHT_RINGS_FAILED = 0x9D7, /* collected <  required (fail)    */

    /*
     * Krazoa Staff acquired - set the frame Fox picks up Krystal's staff in
     * ThornTail Hollow (the first weapon, grabbed after landing from the intro
     * flight). The pickup object sh_staff (dll_01B1) sets it in sh_staff_update
     * when the pickup trigger fires (phase 1 -> 2), and checks it in phase 0 to
     * hide the staff if it has already been taken. Live-verified with a write-
     * watchpoint that caught mainSetBits(0x18b, 1) at sh_staff_update+0x190
     * during the pickup.
     */
    GAMEBIT_STAFF_ACQUIRED = 0x18B,

    /*
     * Set when the Krazoa Staff pickup sequence finishes and unloads the map it
     * had streamed in (sh_staff loads a map while the player is near the staff);
     * sh_staff_update phase-2 "done" path (dll_01B1). Traced to its setter
     * alongside the pickup above; downstream consumer not yet confirmed.
     */
    GAMEBIT_STAFF_PICKUP_MAP_UNLOADED = 0x3B8,

    /*
     * ThornTail Hollow staff-combat tutorial arena - the scripted encounter
     * right after the staff pickup, and the gate progression it drives.
     * Traced end to end live (watchpoints + before/after GameBit diffs).
     *
     * Flow:
     *   1. Crossing an invisible proximity Trigger (dll_0126, variant 0x4b, NO
     *      gamebit gate) sets ARENA_ENTERED (0x239); its whole command list is
     *      the single enter-command mainSetBits(0x239,1). Staff-gating is
     *      positional - you cannot reach this corridor before the pickup.
     *   2. Downstream logic reacts to 0x239 (0x239 is read data-driven, not by
     *      any .c): a door opens, four SharpClaws pour out, the door shuts,
     *      Krystal's head prompts "use the staff in combat", the fight begins.
     *      This sets ARENA_ACTIVE (0x11) and ARENA_ENTRY_SEQ (0x2cf).
     *   3. Each SharpClaw sets one death bit (SHARPCLAW_DEAD_1..4) when killed
     *      (DLL 0xC9 enemy, per-placement deathGamebit).
     *   4. shlevelcontrol (dll_01AE, SH_LevelControl_doEarlyScenes, line 626)
     *      polls all four; once all set it latches ARENA_CLEARED (0x2da), drops
     *      ARENA_ACTIVE (0x11) and sets ARENA_REWARD_UNLOCKED (0x3e7).
     *
     * shlevelcontrol mirrors these bits onto SH map object-groups every frame
     * (line 716+): ARENA_ACTIVE (0x11) -> object-group 0x1a (the in-fight
     * state), ARENA_REWARD_UNLOCKED (0x3e7) -> object-group 0x1b (post-fight).
     *
     * IMPORTANT: clearing the arena does NOT reopen the door the SharpClaws
     * came through. It opens a DIFFERENT door to the first staff ability, the
     * Fire Blaster (GameBit 0x2d), and reveals a red switch above the SharpClaw
     * door. After collecting Fire Blaster you return and shoot that switch to
     * open the SharpClaw door, which leads to the Queen EarthWalker. The
     * 0x11/0x3e7 <-> door/switch mapping is inferred from the group mirroring;
     * the enter/death/clear bits themselves are watchpoint/diff-verified. The
     * four enemy<->death-bit assignments are arbitrary placement order.
     */
    GAMEBIT_STAFF_TUTORIAL_ARENA_ENTERED = 0x239,
    GAMEBIT_STAFF_TUTORIAL_ARENA_ACTIVE = 0x11,
    GAMEBIT_STAFF_TUTORIAL_ARENA_ENTRY_SEQ = 0x2CF,
    GAMEBIT_STAFF_TUTORIAL_SHARPCLAW_DEAD_1 = 0x166,
    GAMEBIT_STAFF_TUTORIAL_SHARPCLAW_DEAD_2 = 0x167,
    GAMEBIT_STAFF_TUTORIAL_SHARPCLAW_DEAD_3 = 0x34A,
    GAMEBIT_STAFF_TUTORIAL_SHARPCLAW_DEAD_4 = 0x36F,
    GAMEBIT_STAFF_TUTORIAL_ARENA_CLEARED = 0x2DA,
    GAMEBIT_STAFF_TUTORIAL_ARENA_REWARD_UNLOCKED = 0x3E7,

    /*
     * Fire Blaster learned - the first staff ability. Reached through the arena
     * reward room: pry the magiccavetop "mushroom" (dll_011F) with the staff to
     * warp into a magic cave, where the generic one-shot ability pickup
     * mcupgrade (dll_02B7) grants it - mcupgrade_update sets the placement's
     * collectedGameBit (0x2d here) when you interact and plays the "learned
     * Fire Blaster" cutscene (NPC dialogue 0x468). This is the ownedGameBit for
     * the Fire Blaster entry in the C-menu staff abilities (gCMenuStaffAbilities:
     * text 0x3fd, icon 0xc7a; see cmenu_item_table.h). mcupgrade is generic -
     * every magic-cave ability (Freeze Blast, etc.) is one of these with a
     * different collectedGameBit. Live-verified with a write-watchpoint that
     * caught mainSetBits(0x2d, 1) in mcupgrade_update on collection. You then
     * return and shoot the red switch (below) to open the SharpClaw/Queen door.
     */
    GAMEBIT_STAFF_ABILITY_FIRE_BLASTER = 0x2D,

    /*
     * The red switch above the SharpClaw door (revealed when the arena clears).
     * After collecting Fire Blaster from the reward room you return and shoot
     * this switch; doing so sets BOTH of these bits together, which (consumed
     * data-driven - no .c reads them) opens the SharpClaw door to the Queen
     * EarthWalker. Live-verified: gave Fire Blaster by setting its owned-bit
     * 0x2d, shot the switch, and a before/after diff showed exactly this pair
     * flip 0->1. Which bit is "switch hit" vs "door open" is not distinguished.
     */
    GAMEBIT_STAFF_TUTORIAL_QUEEN_DOOR_SWITCH_A = 0x2BB,
    GAMEBIT_STAFF_TUTORIAL_QUEEN_DOOR_SWITCH_B = 0x3EA,

    /* ======================================================================
     * Unplaced - meaning verified, but the setter (the story beat that flips
     * the bit) is not yet traced, so these are not yet slotted into the
     * chronological order above.
     * ====================================================================== */

    /*
     * Arwing world-map (flight-select) destination unlocks. worldplanet_init
     * marks planet slot i selectable - WorldPlanetState.unlockedPlanetMask bit i
     * - iff mainGetBit(gWorldPlanetGameBitTable[i]) != 0, so each of these bits
     * ungates one floating-island Arwing destination (an extra per-slot hint gate,
     * gWorldPlanetHintFlagTable + getNextTaskHintText, can still hold it back).
     * Live-verified at the post-prologue map: only Dinosaur Planet's always-on bit
     * (GAMEBIT_WORLDMAP_OPEN = 0xA63, force-set every open) was set, so
     * the mask read 0x04 and only Dinosaur was flyable while these four read 0 and
     * their islands showed the red cross. The id->island->slot mapping is from
     * gWorldPlanetGameBitTable {1019,1018,2659,1020,1017}. Setters not yet traced.
     */
    GAMEBIT_WORLDMAP_UNLOCK_DARKICE_MINES = 0x3F9, /* 1017, slot 4 */
    GAMEBIT_WORLDMAP_UNLOCK_CLOUDRUNNER   = 0x3FA, /* 1018, slot 1 (CloudRunner Fortress) */
    GAMEBIT_WORLDMAP_UNLOCK_WALLED_CITY   = 0x3FB, /* 1019, slot 0 */
    GAMEBIT_WORLDMAP_UNLOCK_DRAGON_ROCK   = 0x3FC, /* 1020, slot 3 */

    /*
     * Arwing world-map destination NAME reveals - a SEPARATE gate from the
     * fly-there unlocks above. worldplanet shows each slot's name via
     * pauseMenuSetupTitle(0x2A7, gWorldPlanetTitleStringIds[slot], ...), which only
     * prints the real name when mainGetBit(gTaskHintTable[idx].bit_id) != 0 and
     * otherwise falls back to text entry 5 = "?". These four ARE those
     * gTaskHintTable[0..4].bit_id values, so they double as the pause-menu
     * task-hint gate for each area. Live-verified: setting 0xA66 flipped Walled
     * City's map name from "?" to its real name while it stayed unflyable (its
     * unlock bit 0x3FB still clear). Dinosaur's name bit is 0xA63 =
     * GAMEBIT_WORLDMAP_OPEN (always set), which is why its name always shows.
     * Setters not yet traced.
     */
    GAMEBIT_WORLDMAP_NAME_DARKICE_MINES = 0xA64,
    GAMEBIT_WORLDMAP_NAME_CLOUDRUNNER   = 0xA65,
    GAMEBIT_WORLDMAP_NAME_WALLED_CITY   = 0xA66,
    GAMEBIT_WORLDMAP_NAME_DRAGON_ROCK   = 0xA67,

    /*
     * The staff abilities learned after Fire Blaster (which IS placed
     * chronologically above, at 0x2D). Each is the ability's ownedGameBit in the
     * C-menu staff-ability section (gCMenuStaffAbilities; see cmenu_item_table.h),
     * granted by an mcupgrade (dll_02B7) pickup carrying that collectedGameBit.
     * Values read straight from the gCMenuStaffAbilities data table
     * (dll_0000_gameui.c); the cave / story beat that grants each is not yet traced.
     */
    GAMEBIT_STAFF_ABILITY_FREEZE_BLAST       = 0x5CE, /* freezes / puts out fires */
    GAMEBIT_STAFF_ABILITY_SHARPCLAW_DISGUISE = 0x40,  /* enemies stop targeting you */
    GAMEBIT_STAFF_ABILITY_GROUND_QUAKE       = 0x107, /* hidden once Super Quake is set */
    GAMEBIT_STAFF_ABILITY_SUPER_QUAKE        = 0xC55, /* upgrade; replaces Ground Quake */
    GAMEBIT_STAFF_ABILITY_OPEN_PORTAL        = 0x5BD, /* opens the large square doors */
    GAMEBIT_STAFF_ABILITY_STAFF_BOOSTER      = 0x957,  /* boost pads reach high ledges */

    /* ======================================================================
     * Imported from Rena Kunisaki's SFA research (data/U0/gamebits.xml in
     * github.com/RenaKunisaki/StarFoxAdventures). Names are rena's and are NOT
     * independently verified here; treat as leads, not ground truth. The value
     * is the global mainGetBit id (xml id, confirmed to match this enum on known
     * bits). Unordered - chronological activation position is unknown. Ids
     * already named above are omitted (their verified names take precedence).
     * ====================================================================== */
    GAMEBIT_SH_KilledBloop1 = 0x5,                       /* table 1 */
    GAMEBIT_SH_KilledBloop2 = 0x8,                       /* table 1 */
    GAMEBIT_SH_TalkedToPepper = 0xB,                     /* table 2; when first landing there */
    GAMEBIT_AndrossRelated0012 = 0x12,                   /* table 0 */
    GAMEBIT_SH_KilledBloop3 = 0x13,                      /* table 1 */
    GAMEBIT_SH_KilledBloop4 = 0x14,                      /* table 1 */
    GAMEBIT_NW_ClimbOnSnowHorn = 0x18,                   /* table 0; climbing onto SnowHorn (will warp you to nearby one) */
    GAMEBIT_NW_ClimbOffSnowHorn = 0x19,                  /* table 0 */
    GAMEBIT_SH_FoundQueen = 0x22,                        /* table 2; hint 256 */
    GAMEBIT_SH_SouthCave_Opening = 0x23,                 /* table 2; ref hollow/HitAnimator target */
    GAMEBIT_ITEM_TrickyBall_Bought = 0x25,               /* table 2 */
    GAMEBIT_DIM_FoundInjuredSnowHorn = 0x27,             /* table 2; hint 284 */
    GAMEBIT_ITEM_AlpineRoot_028 = 0x28,                  /* table 2 */
    GAMEBIT_DIM_ReleasedSnowHorn = 0x2A,                 /* table 2; hint 283; ref snowmines/DIMSnowHornShackle open */
    GAMEBIT_ITEM_DIMShackleKey_Got = 0x2B,               /* table 2; ref snowmines/DIMSnowHornShackle key */
    GAMEBIT_DIMRelated003A = 0x3A,                       /* table 2 */
    GAMEBIT_CF_EnteredFort = 0x41,                       /* table 1; hint 326 */
    GAMEBIT_CF_SavedQueen = 0x43,                        /* table 2; hint 329; ref fortress/CFExplodeFl onExplode */
    GAMEBIT_ITEM_PrisonKey_Got = 0x44,                   /* table 1 */
    GAMEBIT_CFPerchRelated004D = 0x4D,                   /* table 2; ref clouddungeon/HitAnimator target */
    GAMEBIT_ITEM_CFRedCrystal_Got = 0x51,                /* table 2; power gems in CloudRunner Fortress */
    GAMEBIT_ITEM_CFGreenCrystal_Got = 0x52,              /* table 2 */
    GAMEBIT_ITEM_CFBlueCrystal_Got = 0x53,               /* table 2 */
    GAMEBIT_CF_CrystalRelated0054 = 0x54,                /* table 2 */
    GAMEBIT_CF_CrystalRelated0055 = 0x55,                /* table 2 */
    GAMEBIT_CF_CrystalRelated0056 = 0x56,                /* table 2 */
    GAMEBIT_CF_PowerOn = 0x57,                           /* table 2; hint 328; ref clouddungeon/StaffLeverT enabled */
    GAMEBIT_ITEM_CFPowerKey_Used = 0x5F,                 /* table 2; ref fortress/HitAnimator target */
    GAMEBIT_ITEM_CFPowerKey_Got = 0x60,                  /* table 2; ref fortress/CFPowerLock key */
    GAMEBIT_IM_TrickyRelated006E = 0x6E,                 /* table 2; set after Tricky landing scene */
    GAMEBIT_IM_TrickyRelated006F = 0x6F,                 /* table 2; set when entering hut */
    GAMEBIT_IM_RescuedTricky = 0x70,                     /* table 2; hint 261; set at start of bike scene */
    GAMEBIT_IM_RaceStarted = 0x72,                       /* table 2; set when the race actually starts */
    GAMEBIT_ITEM_Staff_Got = 0x75,                       /* table 1; clearing on Galleon restarts ship battle */
    GAMEBIT_WM_Galleon_despawn = 0x78,                   /* table 2 */
    GAMEBIT_IM_StartRace = 0x79,                         /* table 1; setting starts the race scene */
    GAMEBIT_SH_WarpStonePathOpen = 0x88,                 /* table 2; did blow up wall leading to WarpStone */
    GAMEBIT_SH_SouthCave_BombPlanted = 0x8A,             /* table 2; ref hollow/BombPlant exists */
    GAMEBIT_SH_WarpStoneBombPlanted = 0x8B,              /* table 2; ref hollow/BombPlant exists */
    GAMEBIT_SH_Related0090 = 0x90,                       /* table 2; ref hollow/HitAnimator target */
    GAMEBIT_SH_KilledBloop5 = 0x92,                      /* table 1 */
    GAMEBIT_SH_KilledBloop6 = 0x93,                      /* table 1 */
    GAMEBIT_Always1 = 0x95,                              /* table 0; used for always-available shop items */
    GAMEBIT_Always0 = 0x96,                              /* table 0; used for never-available (unused) shop items */
    GAMEBIT_SH_KilledBloop7 = 0x99,                      /* table 1 */
    GAMEBIT_NpcTalkRelated009F = 0x9F,                   /* table 0; related to talking to NPCs */
    GAMEBIT_GalleonRelated00A0 = 0xA0,                   /* table 1 */
    GAMEBIT_WM_GalleonRelated00A4 = 0xA4,                /* table 1 */
    GAMEBIT_WM_SwitchRelatedA7 = 0xA7,                   /* table 0; related to KP pressure switch door; toggled repeatedly during Krystal getting captured scene */
    GAMEBIT_ITEM_FireGem_Count = 0xA9,                   /* table 2; size 2 */
    GAMEBIT_SH_KilledBloop8 = 0xAE,                      /* table 1 */
    GAMEBIT_SH_KilledBloop9 = 0xAF,                      /* table 1 */
    GAMEBIT_SH_KilledBloop10 = 0xB0,                     /* table 1 */
    GAMEBIT_ITEM_Unknown_Used = 0xB4,                    /* table 2; Item name is "Unknown" */
    GAMEBIT_SH_KilledBloop11 = 0xBE,                     /* table 1 */
    GAMEBIT_SH_ReturnedToQueen = 0xBF,                   /* table 2; hint 270; Talked to queen after bringing Tricky back from Ice Mountain */
    GAMEBIT_SH_Entered00C0 = 0xC0,                       /* table 0; also toggled when leaving queen cave, and in CRFort */
    GAMEBIT_ITEM_TrickyFood_Count = 0xC1,                /* table 2; size 4; Number of Tricky foods (GrubTub Fungus) */
    GAMEBIT_ITEM_WhiteGrubTub_Used = 0xC2,               /* table 2; size 3 */
    GAMEBIT_SH_ReturnedToHollow = 0xC3,                  /* table 2; hint 267 */
    GAMEBIT_SH_KilledBloop13 = 0xC4,                     /* table 1 */
    GAMEBIT_SH_KilledBloop14 = 0xC5,                     /* table 1 */
    GAMEBIT_SH_KilledBloop15 = 0xC6,                     /* table 1 */
    GAMEBIT_ITEM_Unknown_Got = 0xC7,                     /* table 2; Item name is "Unknown" */
    GAMEBIT_IM_OnBike = 0xC8,                            /* table 1; set when you can actually steer but also during the cutscene of "rescuing" Tricky */
    GAMEBIT_SH_OpenedTunnelToWell = 0xCC,                /* table 2; ref hollow/HitAnimator target */
    GAMEBIT_IMRelated00CE = 0xCE,                        /* table 2 */
    GAMEBIT_WM_GalleonRelated00D0 = 0xD0,                /* table 2 */
    GAMEBIT_ITEM_TrickyCall_Got = 0xDD,                  /* table 2; hint 264 */
    GAMEBIT_SHBOT_MagicCaveVisible = 0xDE,               /* table 2; ref hollow2/HitAnimator target */
    GAMEBIT_HT_ActNo = 0xDF,                             /* table 1; size 4; Hightop (unused)? */
    GAMEBIT_DF_ActNo = 0xE0,                             /* table 1; size 4; Discovery Falls (unused?) */
    GAMEBIT_SH_ActNo = 0xE1,                             /* table 2; size 4; ThornTail Hollow (top and bottom) */
    GAMEBIT_GM_ActNo = 0xE2,                             /* table 1; size 4; Game Well Maze */
    GAMEBIT_NW_ActNo = 0xE3,                             /* table 2; size 4; SnowHorn Wastes */
    GAMEBIT_WM_ActNo = 0xE4,                             /* table 1; size 4; Krazoa Palace */
    GAMEBIT_CF_ActNo = 0xE5,                             /* table 1; size 4 */
    GAMEBIT_WC_ActNo = 0xE6,                             /* table 1; size 4 */
    GAMEBIT_LV_ActNo = 0xE7,                             /* table 1; size 4; LightFoot Village */
    GAMEBIT_CT_ActNo = 0xE8,                             /* table 1; size 4; CloudTreasure (unused?) */
    GAMEBIT_CD_ActNo = 0xE9,                             /* table 1; size 4; CloudRunner Dungeon */
    GAMEBIT_CA_ActNo = 0xEA,                             /* table 1; size 4; CloudTrap (unused?) */
    GAMEBIT_MMP_ActNo = 0xEB,                            /* table 1; size 4; Moon Mountain Pass */
    GAMEBIT_IM_ActNo = 0xED,                             /* table 1; size 4; Ice Mountain, newicemount, newicemount2, newicemount3 */
    GAMEBIT_CC_ActNo = 0xEE,                             /* table 2; size 4; Cape Claw */
    GAMEBIT_DFSH_ActNo = 0xEF,                           /* table 1; size 4; dfshrine (Test of Combat) */
    GAMEBIT_AnimTest_ActNo = 0xF0,                       /* table 1; size 4 */
    GAMEBIT_SH_KilledBloop16 = 0xF5,                     /* table 1 */
    GAMEBIT_ITEM_SpiritTestFear_Got = 0xFF,              /* table 2; hint 355; have the Krazoa Spirit from Test of Fear (and haven't released it) */
    GAMEBIT_NW_RescuedSnowHornGateKeeper = 0x102,        /* table 2; hint 279 */
    GAMEBIT_SH_KilledBloop17 = 0x104,                    /* table 1 */
    GAMEBIT_ITEM_GroundQuake_Got = 0x107,                /* table 2; hint 308; ref moonpass/MagicCaveTo Collected */
    GAMEBIT_NW_MagicCaveVisible = 0x113,                 /* table 2; ref wastes/MagicCaveTo Visible */
    GAMEBIT_SH_KilledBloop18 = 0x115,                    /* table 1 */
    GAMEBIT_ITEM_FireSpellStone1_Got = 0x123,            /* table 2; hint 297; ref temple/VFP_PodiumP key */
    GAMEBIT_WM_EnteredKrazoaTest1_0129 = 0x129,          /* table 0; set when entering Krazoa test 1, cleared when talking to spirit */
    GAMEBIT_HintTexts0 = 0x12F,                          /* table 2; size 32; related to hint texts; flags, set when Krystal boards ship */
    GAMEBIT_HintTexts1 = 0x130,                          /* table 2; size 32 */
    GAMEBIT_HintTexts2 = 0x131,                          /* table 2; size 32 */
    GAMEBIT_HintTexts3 = 0x132,                          /* table 2; size 32 */
    GAMEBIT_HintTexts4 = 0x133,                          /* table 2; size 32 */
    GAMEBIT_HintTexts5 = 0x134,                          /* table 2; size 32 */
    GAMEBIT_HintTexts6 = 0x135,                          /* table 2; size 32 */
    GAMEBIT_HintTexts7 = 0x136,                          /* table 2; size 32 */
    GAMEBIT_ITEM_Firefly_Count = 0x13D,                  /* table 2; size 5 */
    GAMEBIT_ITEM_FireflyLantern_Got = 0x13E,             /* table 2; hint 273 */
    GAMEBIT_ITEM_BigScarabBag_Got = 0x13F,               /* table 1; hint 375; From rescuing ThornTails from Bloops */
    GAMEBIT_SH_FirstMagicCaveFound = 0x140,              /* table 2; whether entrance is active (glowing, can enter) */
    GAMEBIT_WM_Spirit1Related_0143 = 0x143,              /* table 0; set when collecting first spirit; cleared when it enters krazoa head */
    GAMEBIT_MC_ActNo = 0x144,                            /* table 1; size 4; Magic Cave */
    GAMEBIT_MC_ObjGroups = 0x145,                        /* table 3; size 32 */
    GAMEBIT_SH_WarpStoneRelated015A = 0x15A,             /* table 2; set during intro speech */
    GAMEBIT_CC_UsedCannon = 0x15C,                       /* table 2; hint 402; Used cannon to open route to Ocean Force Point */
    GAMEBIT_OFP_Opened = 0x162,                          /* table 2; hint 338; ref capeclaw/HitAnimator target */
    GAMEBIT_WMRelated0164 = 0x164,                       /* table 2; ref capeclaw/HitAnimator target */
    GAMEBIT_SH_ThornTailRelated0168 = 0x168,             /* table 2 */
    GAMEBIT_ITEM_DIMAlpineRoot_16F = 0x16F,              /* table 2; ref snowmines/CNTColideOb 0x1E */
    GAMEBIT_ITEM_DIMAlpineRoot_Count = 0x170,            /* table 2; size 2 */
    GAMEBIT_ITEM_Spirit6_Got = 0x174,                    /* table 2; hint 422 */
    GAMEBIT_SH_Related0177 = 0x177,                      /* table 2 */
    GAMEBIT_ITEM_DIMCog1_Got = 0x17B,                    /* table 2; ref snowmines/DIMUseObjec key */
    GAMEBIT_ITEM_DIMCog2_Got = 0x17E,                    /* table 2; ref snowmines/TreasureChe item */
    GAMEBIT_ITEM_DIMCog3_Got = 0x17F,                    /* table 2; ref snowmines/TreasureChe item */
    GAMEBIT_ITEM_DIMCog4_Got = 0x180,                    /* table 2; ref snowmines/TreasureChe item */
    GAMEBIT_ITEM_DIMCog1_Used = 0x181,                   /* table 2; ref snowmines/DIMUseObjec open */
    GAMEBIT_ITEM_DIMCog2_Used = 0x182,                   /* table 2; ref snowmines/DIMUseObjec open */
    GAMEBIT_ITEM_DIMCog3_Used = 0x183,                   /* table 2; ref snowmines/DIMUseObjec open */
    GAMEBIT_ITEM_DIMCog4_Used = 0x184,                   /* table 2; ref snowmines/DIMUseObjec open */
    GAMEBIT_Tricky_LoadBadge = 0x186,                    /* table 2 */
    GAMEBIT_IM_SnowRelated0188 = 0x188,                  /* table 2; set when you enter the trigger that starts the snow */
    GAMEBIT_SawBombPlant = 0x189,                        /* table 2 */
    GAMEBIT_SawBombSpore = 0x18E,                        /* table 2 */
    GAMEBIT_SH_FireWeed_190 = 0x190,                     /* table 2 */
    GAMEBIT_SH_FireWeed_191 = 0x191,                     /* table 2 */
    GAMEBIT_SH_FireWeed_192 = 0x192,                     /* table 2 */
    GAMEBIT_ITEM_MoonPassKey_Got = 0x193,                /* table 2; hint 298 */
    GAMEBIT_ITEM_FireWeed_Count = 0x194,                 /* table 2; size 2 */
    GAMEBIT_SawBombPlantPatch = 0x196,                   /* table 2 */
    GAMEBIT_SH_ReturnedAfter4thStone = 0x19C,            /* table 2; hint 408 */
    GAMEBIT_SnowHornArtifact19D = 0x19D,                 /* table 2; set when using artifact */
    GAMEBIT_SnowHornArtifact19F = 0x19F,                 /* table 2; checked when using artifact */
    GAMEBIT_SH_ThornTailRelated01A0 = 0x1A0,             /* table 2; related to ThornTail */
    GAMEBIT_SH_KilledBloop12 = 0x1A1,                    /* table 1 */
    GAMEBIT_ITEM_NWSnowHornArtifact_Got = 0x1A2,         /* table 2; hint 377 */
    GAMEBIT_ITEM_NWSnowHornArtifact_Used = 0x1A3,        /* table 2; hint 378 */
    GAMEBIT_SH_OpenedPathToMagicCave2 = 0x1A4,           /* table 2; ref hollow/HitAnimator target */
    GAMEBIT_NW_MagicCaveCollected = 0x1A6,               /* table 2; ref wastes/MagicCaveTo Collected */
    GAMEBIT_SH_WarpStoneRelated01A8 = 0x1A8,             /* table 0; toggled when talking to WarpStone, and in CRFort */
    GAMEBIT_SH_MetQueen = 0x1AB,                         /* table 2 */
    GAMEBIT_SH_SouthCave_Open = 0x1AC,                   /* table 2; ref hollow/SH_BombWall onExplode */
    GAMEBIT_PlantedBombSpore = 0x1AD,                    /* table 2; hint 257; ref hollow/SH_BombWall onExplode */
    GAMEBIT_SH_MagicCaveCollected = 0x1AE,               /* table 2; ref hollow/MagicCaveTo Collected */
    GAMEBIT_SH_BombPlantedBesideWarpStone = 0x1B4,       /* table 2; ref hollow/BombPlant exists */
    GAMEBIT_CC_MagicCaveCollected = 0x1B6,               /* table 2; ref capeclaw/MagicCaveTo Collected */
    GAMEBIT_SH_CaveOpenedBesideWarpStone = 0x1B7,        /* table 2; ref hollow/HitAnimator target */
    GAMEBIT_MagicCaveExitWarp = 0x1B8,                   /* table 2; size 8; WARPTAB index that magic cave will exit to */
    GAMEBIT_IM_TrickyRelated01B9 = 0x1B9,                /* table 0; set when starting Tricky landing scene */
    GAMEBIT_IM_SlippyWarnedCold = 0x1BD,                 /* table 2 */
    GAMEBIT_ITEM_GiveScarabs_Count = 0x1BE,              /* table 2; size 8; Money (in Give Scarabs option) */
    GAMEBIT_IM_TriggerSlippy = 0x1BF,                    /* table 2; Set to trigger Slippy's "water is cold" warning if not already seen */
    GAMEBIT_ITEM_NWKey_Got2 = 0x1C3,                     /* table 2; hint 322 */
    GAMEBIT_CC_Located = 0x1C4,                          /* table 2; hint 317 */
    GAMEBIT_BaddieRelated1C8 = 0x1C8,                    /* table 0 */
    GAMEBIT_IM_TrickyRelated01D6 = 0x1D6,                /* table 3; set when starting Tricky landing scene, cleared after race */
    GAMEBIT_ITEM_DeletedSpell1D7 = 0x1D7,                /* table 2; in spell bits table but does nothing */
    GAMEBIT_DIM_ReachedBoss = 0x1DF,                     /* table 1; hint 292 */
    GAMEBIT_DIM_LocatedCogs = 0x1E5,                     /* table 2; hint 287; ref snowmines/HitAnimator target */
    GAMEBIT_IM_TrickyRelated01ED = 0x1ED,                /* table 3; set when warping to Ice Mountain, cleared when starting Tricky landing scene */
    GAMEBIT_ITEM_DinoHorn_Got = 0x1EE,                   /* table 2; hint 288; ref snowmines/DIMUseObjec key */
    GAMEBIT_ITEM_DIM2CellKey_Got = 0x1F1,                /* table 2; ref snowmines2/DIM2CellKey key */
    GAMEBIT_ITEM_DIMSilverKey_Got = 0x1F3,               /* table 2; ref snowmines2/DIM2CellKey key */
    GAMEBIT_DIM_CrossedBlizzard = 0x1FA,                 /* table 2; hint 289 */
    GAMEBIT_SnowBikeRelated01FB = 0x1FB,                 /* table 2 */
    GAMEBIT_WM_FoundKrystal = 0x1FC,                     /* table 2; hint 315; Reached top of Krazoa Palace */
    GAMEBIT_ITEM_WCSunStone_Got = 0x201,                 /* table 2 */
    GAMEBIT_ITEM_WCSunStone_Used = 0x202,                /* table 2 */
    GAMEBIT_ITEM_DIM2CellKey_Used = 0x207,               /* table 2; ref snowmines2/DIM2CellKey open */
    GAMEBIT_ITEM_DIMSilverKey_Used = 0x208,              /* table 2; ref snowmines2/DIM2CellKey open */
    GAMEBIT_CF_FlewTo = 0x212,                           /* table 1; hint 324 */
    GAMEBIT_ITEM_DIMGoldKey_Used = 0x219,                /* table 2 */
    GAMEBIT_ITEM_DIMSilverKey_Used_2 = 0x21A,            /* table 2 */
    GAMEBIT_WM_SpiritHead1Fired = 0x21D,                 /* table 1; when releasing spirit 1, head fired laser */
    GAMEBIT_DIM_FoundBelinaTe = 0x223,                   /* table 2; hint 290 */
    GAMEBIT_DIM3_ActNo = 0x229,                          /* table 1; size 4; snowmines3 (unused?) */
    GAMEBIT_ITEM_FireSpellStone1_Used = 0x22B,           /* table 2 */
    GAMEBIT_WC_PlacedSunMoonStones = 0x235,              /* table 2; hint 411 */
    GAMEBIT_SH_MagicCaveVisible = 0x23A,                 /* table 1; ref hollow/MagicCaveTo Visible */
    GAMEBIT_SH_Related023C = 0x23C,                      /* table 2 */
    GAMEBIT_SH_ThornTailRelated023D = 0x23D,             /* table 1; related to ThornTail */
    GAMEBIT_ITEM_SilverKey241_Got = 0x241,               /* table 0 */
    GAMEBIT_ITEM_SilverKey241_Used = 0x242,              /* table 2 */
    GAMEBIT_ITEM_WCMoonStone_Used = 0x243,               /* table 2 */
    GAMEBIT_ITEM_TrickyFlame_Got = 0x245,                /* table 2 */
    GAMEBIT_MagicCaveDoorClosed = 0x246,                 /* table 2; controls iron gate and switches in 1st cave */
    GAMEBIT_WM_DoorToKrazTest1Opened = 0x24E,            /* table 2; ref warlock/HitAnimator target */
    GAMEBIT_ITEM_WCGoldTooth_Used = 0x25A,               /* table 2 */
    GAMEBIT_ITEM_WCSilverTooth_Used = 0x25B,             /* table 2 */
    GAMEBIT_ITEM_WCMoonStone_Got = 0x264,                /* table 2 */
    GAMEBIT_PushableRelated0272 = 0x272,                 /* table 2; ref snowmines2/HitAnimator target */
    GAMEBIT_ITEM_Spirit1_Used = 0x277,                   /* table 1 */
    GAMEBIT_ITEM_SilverKey282_Got = 0x282,               /* table 2 */
    GAMEBIT_ITEM_SilverKey282_Used = 0x283,              /* table 2 */
    GAMEBIT_MagicCaveDoorRelated028A = 0x28A,            /* table 2; related to iron gate, unsure of purpose */
    GAMEBIT_ITEM_Spirit2_Used = 0x29A,                   /* table 2; hint 316 */
    GAMEBIT_TransporterRelated029B = 0x29B,              /* table 2 */
    GAMEBIT_SH_OpenedGateToCape = 0x2B2,                 /* table 2; ref hollow/StaffLeverO activated */
    GAMEBIT_LV_CapturedByLightFoot = 0x2B5,              /* table 2; hint 346 */
    GAMEBIT_LV_TestStrengthBestTime1 = 0x2B6,            /* table 2; size 16 */
    GAMEBIT_LV_TestTrackingBestTime1 = 0x2B7,            /* table 2; size 16 */
    GAMEBIT_ENV_dayNo = 0x2BA,                           /* table 3; size 8; Counts from 0 to 27, increasing every morning in-game time. Used for environmental effects. */
    GAMEBIT_SH_FirstMagicCaveDoorOpen = 0x2C0,           /* table 2; ref hollow/HitAnimator target */
    GAMEBIT_IM_TrickyRelated02C1 = 0x2C1,                /* table 0; set when starting tricky landing scene */
    GAMEBIT_DIM_ReachedBottom = 0x2C3,                   /* table 2; hint 291 */
    GAMEBIT_LV_TestTrackingBestTime2 = 0x2CB,            /* table 2; size 16 */
    GAMEBIT_LV_TestTrackingBestTime3 = 0x2CC,            /* table 2; size 16 */
    GAMEBIT_LV_EscapedFromPole = 0x2D0,                  /* table 2; hint 347 */
    GAMEBIT_ITEM_FireGem_Got = 0x2D6,                    /* table 1 */
    GAMEBIT_LV_TestStrengthBestTime2 = 0x2D7,            /* table 2; size 16 */
    GAMEBIT_LV_TestStrengthBestTime3 = 0x2D8,            /* table 2; size 16 */
    GAMEBIT_LV_ChiefStartedTest = 0x2E7,                 /* table 2; hint 348 */
    GAMEBIT_ITEM_WaterSpellStone1_Got = 0x2E8,           /* table 2; hint 336; ref dfptop/VFP_PodiumP key */
    GAMEBIT_CFRelated02FC = 0x2FC,                       /* table 1 */
    GAMEBIT_CFRelated02FD = 0x2FD,                       /* table 1 */
    GAMEBIT_CFRelated02FE = 0x2FE,                       /* table 1 */
    GAMEBIT_CFRelated02FF = 0x2FF,                       /* table 1 */
    GAMEBIT_ITEM_Key336_Got = 0x336,                     /* table 1; XXX where is this key from? */
    GAMEBIT_FinalBoss_ActNo = 0x349,                     /* table 1; size 4 */
    GAMEBIT_WC_ObjGroups = 0x36A,                        /* table 3; size 32 */
    GAMEBIT_KrazTest1Related0372 = 0x372,                /* table 3; set when entering Krazoa test 1, cave beside WarpStone */
    GAMEBIT_DIM2_ObjGroups = 0x373,                      /* table 3; size 32 */
    GAMEBIT_IM_DoorOpen = 0x377,                         /* table 2; ref newicemount/HitAnimator target */
    GAMEBIT_IM_BikeRelated0378 = 0x378,                  /* table 1; set when approaching SharpClaws in hut, cleared after race */
    GAMEBIT_IM_BikeRelated0379 = 0x379,                  /* table 2; set to 0x19 when finishing race even though max is 1 - in kiosk, related to demo mode - map 0x19 is newicemount3 */
    GAMEBIT_IM_FinishedRace = 0x37A,                     /* table 2; hint 262 */
    GAMEBIT_IMRelated037B = 0x37B,                       /* table 2 */
    GAMEBIT_IM_HutRelated0382 = 0x382,                   /* table 2; changed when near hut */
    GAMEBIT_KrazTest1Related0390 = 0x390,                /* table 3; set when entering Krazoa test 1, cleared when talking to WarpStone */
    GAMEBIT_DBAY_ObjGroups = 0x397,                      /* table 3; size 32 */
    GAMEBIT_IM_WaterRelated03A0 = 0x3A0,                 /* table 3; set when getting out of water */
    GAMEBIT_IM_Done = 0x3A1,                             /* table 3; Tricky now follows you */
    GAMEBIT_IM_BikeRelated03A2 = 0x3A2,                  /* table 1; set when gaining control of bike, cleared at end */
    GAMEBIT_IM_BikeRelated03A3 = 0x3A3,                  /* table 1; cleared at end of race */
    GAMEBIT_SH_Related03AA = 0x3AA,                      /* table 2 */
    GAMEBIT_ENV_disableDayFX1 = 0x3AB,                   /* table 3 */
    GAMEBIT_ENV_disableDayFX2 = 0x3AC,                   /* table 3; disable an environment effect */
    GAMEBIT_IM_ObjGroups = 0x3AD,                        /* table 3; size 32 */
    GAMEBIT_IM_EnteredHut = 0x3AE,                       /* table 2 */
    GAMEBIT_ENV_isOutdoor = 0x3B0,                       /* table 3; disable rain, snow */
    GAMEBIT_CC_ObjGroups = 0x3B7,                        /* table 3; size 32 */
    GAMEBIT_IM_BikeRelated03B9 = 0x3B9,                  /* table 1; set when approaching SharpClaws in hut, cleared after race */
    GAMEBIT_IM_BikeRelated03BA = 0x3BA,                  /* table 2; set at some point during race */
    GAMEBIT_DIM_CapturedCannon = 0x3CF,                  /* table 2; hint 286 */
    GAMEBIT_ITEM_DinoHorn_3D8 = 0x3D8,                   /* table 0 */
    GAMEBIT_SB_ObjGroups = 0x3E0,                        /* table 3; size 32; frontend, galleonship, Ship Battle */
    GAMEBIT_DIM_TriggerLostInBlizzard = 0x3E2,           /* table 0; Trigger scene where Fox walks off into blizzard and comes back */
    GAMEBIT_NW_SnowHorn03E3 = 0x3E3,                     /* table 0; related to riding SnowHorn */
    GAMEBIT_DIM_LostInBlizzard = 0x3E8,                  /* table 0; Triggered by 0x3E2, actually starts the scene */
    GAMEBIT_ITEM_NWFood_Got = 0x3E9,                     /* table 0; Alpine Root while riding SnowHorn through blizzard; collecting one sets this to 1, then 0 */
    GAMEBIT_DBAY_ActNo = 0x3EE,                          /* table 1; size 4 */
    GAMEBIT_ITEM_CCGoldBar_Used = 0x3F0,                 /* table 2; size 3 */
    GAMEBIT_ITEM_DinoHorn_3F1 = 0x3F1,                   /* table 0 */
    GAMEBIT_ITEM_HighTopGold_Found = 0x3F4,              /* table 2; hint 319 */
    GAMEBIT_ITEM_FuelCell_Count = 0x3F5,                 /* table 2; size 8 */
    GAMEBIT_ITEM_TrickyBall_Usable = 0x3F8,              /* table 2; set after throwing and you can throw multiple balls! */
    GAMEBIT_WorldMapCloudFort = 0x3FA,                   /* table 2; hint 323; unlocked CloudRunner Fortress on world map */
    GAMEBIT_WorldMapWallCity = 0x3FB,                    /* table 2; hint 359; unlocked Walled City on world map */
    GAMEBIT_WorldMapDragRock = 0x3FC,                    /* table 2; hint 384; unlocked Dragon Rock on world map */
    GAMEBIT_WM_ObjGroups = 0x405,                        /* table 3; size 32 */
    GAMEBIT_SH_FuelCell_QueenCave = 0x416,               /* table 2; ref hollow/fuelCell Collected */
    GAMEBIT_SH_FuelCell_BesideWarpStone1 = 0x418,        /* table 2; ref hollow/fuelCell Collected */
    GAMEBIT_SH_FuelCell_BesideWarpStone2 = 0x41A,        /* table 2; ref hollow/fuelCell Collected */
    GAMEBIT_InsideGal_ObjGroups = 0x421,                 /* table 3; size 32 */
    GAMEBIT_WM_GalleonRelated429 = 0x429,                /* table 2; related to savegame/obj groups/galleon */
    GAMEBIT_MMP_ObjGroups = 0x42E,                       /* table 3; size 32 */
    GAMEBIT_DIM3_ObjGroups = 0x443,                      /* table 3; size 32 */
    GAMEBIT_MenuRelated044F = 0x44F,                     /* table 0; set by n_rareware DLL */
    GAMEBIT_SH_ObjGroups = 0x452,                        /* table 3; size 32; also LinkG 0x00: bloops 0x06: switch to open Queen cave? */
    GAMEBIT_ITEM_MMPKey_Used = 0x453,                    /* table 2; hint 299; ref moonpass/HitAnimator target */
    GAMEBIT_CF_ObjGroups = 0x458,                        /* table 3; size 32 */
    GAMEBIT_CT_ObjGroups = 0x45A,                        /* table 3; size 32 */
    GAMEBIT_DBSH_ObjGroups = 0x473,                      /* table 3; size 32 */
    GAMEBIT_GM_ObjGroups = 0x47B,                        /* table 3; size 32 */
    GAMEBIT_CD_ObjGroups = 0x47C,                        /* table 3; size 32 */
    GAMEBIT_DF_ObjGroups = 0x480,                        /* table 3; size 32 */
    GAMEBIT_IM_FuelCell_CheatCave = 0x484,               /* table 2; ref newicemount/fuelCell Collected */
    GAMEBIT_DIM_ActNo = 0x492,                           /* table 1; size 4 */
    GAMEBIT_DIM_ObjGroups = 0x493,                       /* table 3; size 32 */
    GAMEBIT_SpellStoneRelated049A = 0x49A,               /* table 1 */
    GAMEBIT_CF_DiscoveredGoldMine = 0x49B,               /* table 1; hint 331 */
    GAMEBIT_CF_ObjGroups2 = 0x4A3,                       /* table 3; size 32 */
    GAMEBIT_LV_ObjGroups = 0x4A6,                        /* table 3; size 32 */
    GAMEBIT_WM_KrazSpirit1Returning = 0x4A7,             /* table 0; set when the spirit is visible */
    GAMEBIT_WaterSpellStone1_4AB = 0x4AB,                /* table 1; related to spellstone */
    GAMEBIT_NW_ObjGroups = 0x4AE,                        /* table 3; size 32; also LinkB */
    GAMEBIT_TargetRelated04B7 = 0x4B7,                   /* table 1; related to object targeting */
    GAMEBIT_IM_PushBlock_Placed = 0x4D3,                 /* table 2 */
    GAMEBIT_CFPowerRelated04E0 = 0x4E0,                  /* table 1 */
    GAMEBIT_TrickyTalk = 0x4E3,                          /* table 0; size 8; if < FF, can talk to Tricky, but he won't say anything */
    GAMEBIT_Tricky_Usable = 0x4E4,                       /* table 2; can use Tricky commands */
    GAMEBIT_IM_DoneRace = 0x4E5,                         /* table 2; Completed first race */
    GAMEBIT_ITEM_SpellStone1_Used = 0x4E9,               /* table 2; hint 305 */
    GAMEBIT_FoundSpellStoneWarpPad = 0x4FA,              /* table 2; hint 372; ref temple/HitAnimator target */
    GAMEBIT_VFP_ActNo = 0x4FE,                           /* table 2; size 4 */
    GAMEBIT_VFP_ObjGroups = 0x500,                       /* table 3; size 32 */
    GAMEBIT_TransporterRelated0511 = 0x511,              /* table 2 */
    GAMEBIT_AnimTest_ObjGroups = 0x517,                  /* table 3; size 32 */
    GAMEBIT_DIM_Entered540 = 0x540,                      /* table 1 */
    GAMEBIT_ITEM_TrickyStayFind_Got = 0x544,             /* table 2; hint 263 */
    GAMEBIT_TREX_ActNo = 0x547,                          /* table 1; size 4 */
    GAMEBIT_TREX_ObjGroups = 0x548,                      /* table 3; size 32 */
    GAMEBIT_WC_Unk0564 = 0x564,                          /* table 2 */
    GAMEBIT_ITEM_IMAlpineRoot_Count = 0x576,             /* table 2; size 3 */
    GAMEBIT_ITEM_AlpineRoot_Used = 0x578,                /* table 2; size 3 */
    GAMEBIT_NoMapData = 0x58D,                           /* table 0; Force No Map Data */
    GAMEBIT_ITEM_MapVFP_Got = 0x59D,                     /* table 2; Have Volcano Force Point Map */
    GAMEBIT_ITEM_MapDIM_Got = 0x59E,                     /* table 2; Have DarkIce Mines Map */
    GAMEBIT_ITEM_MapNW_Got = 0x5A0,                      /* table 2; Have SnowHorn Wastes Map */
    GAMEBIT_ITEM_MapCF_Got = 0x5A1,                      /* table 2; Have CloudRunner Fortress Map */
    GAMEBIT_ITEM_MapLV_Got = 0x5A2,                      /* table 2; Have LightFoot Village Map */
    GAMEBIT_ITEM_MapSH_Got = 0x5A3,                      /* table 2; Have ThornTail Hollow Map */
    GAMEBIT_NW_SnowHown05BA = 0x5BA,                     /* table 0; related to riding SnowHorn */
    GAMEBIT_NW_SnowHown05BB = 0x5BB,                     /* table 0; related to riding SnowHorn */
    GAMEBIT_ITEM_OpenPortal_Got = 0x5BD,                 /* table 2; ref hollow/MagicCaveTo Collected */
    GAMEBIT_ITEM_IceBlast_Got = 0x5CE,                   /* table 2; hint 302; ref temple/MagicCaveTo Collected */
    GAMEBIT_KrazTest_ActNo = 0x5D0,                      /* table 1; size 4; also dfptop */
    GAMEBIT_KrazTest_ObjGroups = 0x5D1,                  /* table 3; size 32; also dfptop */
    GAMEBIT_ITEM_FireflyNotShown_Count = 0x5D6,          /* table 2; size 5 */
    GAMEBIT_DR_ObjGroups = 0x5DB,                        /* table 3; size 32 */
    GAMEBIT_DRBOT_ObjGroups = 0x5DC,                     /* table 3; size 32 */
    GAMEBIT_ITEM_SpellStone2_Used = 0x5F3,               /* table 2; hint 342 */
    GAMEBIT_ITEM_SpellStone4_Used = 0x5F4,               /* table 2; hint 405 */
    GAMEBIT_ITEM_DeletedSpell5FC_Got = 0x5FC,            /* table 2; in spell bits table but does nothing */
    GAMEBIT_SHOP_ObjGroups = 0x601,                      /* table 3; size 32 */
    GAMEBIT_DR_RescuedCloudRunner = 0x609,               /* table 2; hint 393; ref dragrock/HitAnimator target */
    GAMEBIT_ITEM_MMPKey_Got = 0x611,                     /* table 2; ref moonpass/MMP_padlock key */
    GAMEBIT_SHOP_Unk0617 = 0x617,                        /* table 0; set when entering shop */
    GAMEBIT_LV_DoneTests = 0x61C,                        /* table 2; hint 349 */
    GAMEBIT_SHOP_ScarabGameRunning = 0x626,              /* table 0; ref swapstore/HitAnimator target */
    GAMEBIT_DR_RescuedHighTop = 0x632,                   /* table 2; hint 391; ref dragrock/HitAnimator target */
    GAMEBIT_SC_totempuzzle_running = 0x639,              /* table 2 */
    GAMEBIT_ITEM_SpellStone3_Got = 0x63C,                /* table 2; hint 373 */
    GAMEBIT_TumbleweedRelated642 = 0x642,                /* table 0 */
    GAMEBIT_ITEM_LVBlock2_Used = 0x647,                  /* table 2; ref swapcircle/SC_blockpla open */
    GAMEBIT_SH_Landed064B = 0x64B,                       /* table 0; set when Fox first steps foot on the planet; cleared after Pepper scene */
    GAMEBIT_ITEM_DinoHorn_651 = 0x651,                   /* table 2 */
    GAMEBIT_ITEM_BombSpore_Count = 0x66C,                /* table 2; size 3 */
    GAMEBIT_ITEM_WhiteShroom_Count = 0x66D,              /* table 2; size 3 */
    GAMEBIT_WM_Bafomdad1_Got = 0x703,                    /* table 2; hidden passage at start */
    GAMEBIT_DR_ActNo = 0x76E,                            /* table 1; size 4 */
    GAMEBIT_DRBOT_ActNo = 0x76F,                         /* table 1; size 4 */
    GAMEBIT_ITEM_DeletedSpell777_Got = 0x777,            /* table 2; in spell bits table but does nothing */
    GAMEBIT_ITEM_SpellStone7BD_Got = 0x7BD,              /* table 2; unused? */
    GAMEBIT_ITEM_SpellStone7BF_Got = 0x7BF,              /* table 1 */
    GAMEBIT_OFP_Reopened = 0x7C2,                        /* table 2; hint 403; ref dfptop/HitAnimator target */
    GAMEBIT_HT_ObjStates = 0x7CE,                        /* table 3; size 32 */
    GAMEBIT_ITEM_MapDR_Got = 0x7DD,                      /* table 2 */
    GAMEBIT_ITEM_MapWM_Got = 0x7E5,                      /* table 2 */
    GAMEBIT_ITEM_MapOFP_Got = 0x7E9,                     /* table 2 */
    GAMEBIT_WC_LitBeacons = 0x7F8,                       /* table 2; hint 362; ref wallcity/HitAnimator target */
    GAMEBIT_WC_FoundKing = 0x7FC,                        /* table 2; hint 363 */
    GAMEBIT_WC_OpenedSunMoonAreas = 0x817,               /* table 2; hint 410; ref wallcity/HitAnimator target */
    GAMEBIT_WC_FlewTo = 0x818,                           /* table 2; hint 360; ref wallcity/Landed_Arwi Visible */
    GAMEBIT_WC_OpenedBossDoor = 0x819,                   /* table 2; hint 365; ref wallcity/HitAnimator target */
    GAMEBIT_ITEM_WCSilverTooth_Got = 0x81D,              /* table 2; ref wallcity/TreasureChe item */
    GAMEBIT_ITEM_WCGoldTooth_Got = 0x81E,                /* table 2; ref wallcity/TreasureChe item */
    GAMEBIT_ITEM_MapWC_Got = 0x82E,                      /* table 2 */
    GAMEBIT_ITEM_MapCC_Got = 0x82F,                      /* table 2 */
    GAMEBIT_ITEM_MapMMP_Got = 0x835,                     /* table 2 */
    GAMEBIT_ITEM_SpellStone83A_Got = 0x83A,              /* table 2; unused? */
    GAMEBIT_ITEM_FireSpellStone2_Got = 0x83B,            /* table 2; hint 369; ref temple/VFP_PodiumP key */
    GAMEBIT_ITEM_WaterSpellStone2_Got = 0x83C,           /* table 2; hint 401; ref dfptop/VFP_PodiumP key */
    GAMEBIT_ITEM_MoonSeed_Used = 0x857,                  /* table 2; hint 309; ref moonpass/HitAnimator target */
    GAMEBIT_DIM2_CannonRelated085E = 0x85E,              /* table 2; ref snowmines2/HitAnimator target */
    GAMEBIT_ITEM_MoonSeed_Count = 0x86A,                 /* table 2; size 3 */
    GAMEBIT_DIM2_CannonRelated0874 = 0x874,              /* table 2; ref snowmines2/HitAnimator target */
    GAMEBIT_MMPAsteroidRelated087B = 0x87B,              /* table 2; size 2 */
    GAMEBIT_SH_WarpStoneRelated0884 = 0x884,             /* table 2 */
    GAMEBIT_ITEM_RockCandyRelated0886 = 0x886,           /* table 2; related to rock candy */
    GAMEBIT_SH_SawWarpStoneIntro = 0x887,                /* table 2 */
    GAMEBIT_MMP_MovedMeteor = 0x89B,                     /* table 2; hint 310; ref moonpass/HitAnimator target */
    GAMEBIT_ITEM_Unknown8A0_Got = 0x8A0,                 /* table 2; hint 357; Hint text is "Released Third Krazoa Spirit" */
    GAMEBIT_WM_Warp1Enabled = 0x8A1,                     /* table 2; ref warlock/Transporter enabled */
    GAMEBIT_ITEM_Unknown8A0_Used = 0x8A2,                /* table 2; set at chapter 4 */
    GAMEBIT_KP_ActNo = 0x8EC,                            /* table 1; size 4; old "krazoapalace" map */
    GAMEBIT_KP_ObjGroups = 0x8ED,                        /* table 3; size 32 */
    GAMEBIT_ITEM_WaterSpellStone1_902 = 0x902,           /* table 1 */
    GAMEBIT_WM_SwitchCamActive = 0x905,                  /* table 2; camera pointing at door opened by pressure switch */
    GAMEBIT_SawMagic = 0x90D,                            /* table 2; Have collected a Staff Energy Gem (if 0, explain it when you collect one) */
    GAMEBIT_SawBigHealth = 0x90E,                        /* table 2 */
    GAMEBIT_SawApple = 0x90F,                            /* table 2; small health pickup */
    GAMEBIT_SawScarab = 0x910,                           /* table 2 */
    GAMEBIT_SawWarpPad = 0x912,                          /* table 2; if not, explains what it is when touching one */
    GAMEBIT_PushableRelated0913 = 0x913,                 /* table 2 */
    GAMEBIT_ITEM_50ScarabBag_Got = 0x919,                /* table 2 */
    GAMEBIT_ITEM_100ScarabBag_Got = 0x91A,               /* table 2 */
    GAMEBIT_ITEM_200ScarabBag_Got = 0x91B,               /* table 2 */
    GAMEBIT_ITEM_WMGoldKey_Got = 0x91C,                  /* table 1; opens door to barrel at start as Krystal; collecting this also enables C menu */
    GAMEBIT_MC_IsExiting = 0x91E,                        /* table 0; set to respawn from cave entrance */
    GAMEBIT_LearnedToSpeak = 0x92A,                      /* table 2; Told how to speak to NPCs */
    GAMEBIT_SawCMenuExplanation = 0x930,                 /* table 2 */
    GAMEBIT_CF_EscapedDungeon = 0x939,                   /* table 2; hint 327; Exploded dungeon ceiling to be able to get disguise */
    GAMEBIT_CF_RescuedBabies = 0x940,                    /* table 2; hint 330 */
    GAMEBIT_CF_HaveStaff = 0x94E,                        /* table 2 */
    GAMEBIT_CF_NotRecoveredStaff = 0x94F,                /* table 2 */
    GAMEBIT_ITEM_Flute_Got = 0x953,                      /* table 2 */
    GAMEBIT_FlewToPlanet = 0x956,                        /* table 2; hint 253; ref hollow/Landed_Arwi Visible */
    GAMEBIT_ITEM_StaffBooster_Got = 0x957,               /* table 2; hint 272; ref hollow2/MagicCaveTo Collected */
    GAMEBIT_ITEM_LaserSpell_Got = 0x958,                 /* table 2; Have Rapid Fire Laser Spell (unused) */
    GAMEBIT_ITEM_PortalSpell_Disabled = 0x960,           /* table 2 */
    GAMEBIT_ITEM_Spell0961_Disabled = 0x961,             /* table 2; set when Krystal loses staff, cleared when Fox finds it */
    GAMEBIT_ITEM_StaffBooster_Disabled = 0x964,          /* table 2 */
    GAMEBIT_ITEM_Spell0965_Disabled = 0x965,             /* table 2; set when Krystal loses staff, cleared when Fox finds it */
    GAMEBIT_ITEM_DinoHorn_Disabled = 0x966,              /* table 3 */
    GAMEBIT_ITEM_Firefly_Disabled = 0x967,               /* table 2; disables lantern in menu */
    GAMEBIT_Tricky_CantFeed = 0x968,                     /* table 3 */
    GAMEBIT_ITEM_SharpClawDisguise_Disabled = 0x969,     /* table 2 */
    GAMEBIT_ITEM_SuperQuake_Disabled = 0x96B,            /* table 2 */
    GAMEBIT_CF_DoStandUpAnim = 0x970,                    /* table 1; triggers a falling and getting back up scene on map reload */
    GAMEBIT_CFLever0974 = 0x974,                         /* table 2; ref fortress/StaffLeverO activated */
    GAMEBIT_CFLever0975 = 0x975,                         /* table 2; ref fortress/StaffLeverO activated */
    GAMEBIT_CFRelated0983 = 0x983,                       /* table 3 */
    GAMEBIT_CFRelated0984 = 0x984,                       /* table 3 */
    GAMEBIT_ITEM_FireBlaster_Disabled = 0x986,           /* table 2 */
    GAMEBIT_FoxSawKrazoa = 0x9A6,                        /* table 2; hint 307 */
    GAMEBIT_CollectedFlag09A8 = 0x9A8,                   /* table 2; did collect something (moon seed?) */
    GAMEBIT_WM_KrystalLanded = 0x9AA,                    /* table 2; hint 246; Krystal encountered General Scales */
    GAMEBIT_WM_KrystalTalkedToDinoAfterTest1 = 0x9AB,    /* table 2 */
    GAMEBIT_DR_HighTopSwitch1 = 0x9C7,                   /* table 1 */
    GAMEBIT_DR_HighTopSwitch2 = 0x9C9,                   /* table 1 */
    GAMEBIT_DR_HighTopSwitch3 = 0x9CB,                   /* table 1 */
    GAMEBIT_DR_HighTopSwitch4 = 0x9CD,                   /* table 1 */
    GAMEBIT_IncomingCommunication = 0x9D5,               /* table 0; Slippy calling you */
    GAMEBIT_ArwingRelated09D6 = 0x9D6,                   /* table 1 */
    GAMEBIT_DR_FlewTo = 0x9E9,                           /* table 2; hint 385; cleared when Arwing flies to Dragon Rock */
    GAMEBIT_DR_EnteredDrakorTower = 0x9F3,               /* table 2; hint 394 */
    GAMEBIT_DIM_RodeSnowHornThroughGates = 0x9F6,        /* table 2; hint 285; ref snowmines/HitAnimator target */
    GAMEBIT_PushableRelated0A1A = 0xA1A,                 /* table 0 */
    GAMEBIT_DIM_CannonRelated0A21 = 0xA21,               /* table 2; related to DIM cannon */
    GAMEBIT_SH_RescuedEggs = 0xA31,                      /* table 1; hint 358; ref hollow/CNTstopwatc target */
    GAMEBIT_SBRelated0A3C = 0xA3C,                       /* table 0 */
    GAMEBIT_SB_IsRaining = 0xA3D,                        /* table 0 */
    GAMEBIT_SBRelated0A3E = 0xA3E,                       /* table 0 */
    GAMEBIT_SBRelated0A3F = 0xA3F,                       /* table 0 */
    GAMEBIT_VFP_ReturnedWithSpellStone = 0xA43,          /* table 2; hint 370; ref temple/HitAnimator target */
    GAMEBIT_SB_DoorOpen = 0xA4B,                         /* table 0; ref frontend/HitAnimator target */
    GAMEBIT_WM_DestroyedWall1 = 0xA58,                   /* table 2; cracked wall to inside as Krystal */
    GAMEBIT_WM_Wall1Related0A59 = 0xA59,                 /* table 2; set after blowing up wall */
    GAMEBIT_WM_DestroyedWall2 = 0xA5A,                   /* table 2; past flamethrowers */
    GAMEBIT_WM_Wall2Related0A5B = 0xA5B,                 /* table 2; ref warlock/ExplodeWall onExplode */
    GAMEBIT_ECSH_OpenedDoor_0A5F = 0xA5F,                /* table 2 */
    GAMEBIT_ECSH_PushedSwitch = 0xA60,                   /* table 0; opens 2nd door temporarily */
    GAMEBIT_ECSH_BarrelSpawning = 0xA61,                 /* table 0 */
    GAMEBIT_FinalBoss_ObjGroups = 0xA62,                 /* table 3; size 32 */
    GAMEBIT_WorldMapRelated0A66 = 0xA66,                 /* table 2 */
    GAMEBIT_SBRelated0A71 = 0xA71,                       /* table 0 */
    GAMEBIT_WM_DestroyedBox1 = 0xA72,                    /* table 2; box blocking ramp at start */
    GAMEBIT_WM_DestroyedBox2 = 0xA74,                    /* table 2 */
    GAMEBIT_WM_DestroyedBox3 = 0xA75,                    /* table 2 */
    GAMEBIT_WM_DestroyedBox4 = 0xA77,                    /* table 2 */
    GAMEBIT_EnableCMenu = 0xA7B,                         /* table 1; set when collecting key on ship */
    GAMEBIT_WMRelated0A7F = 0xA7F,                       /* table 3; related to music? toggled constantly in KP */
    GAMEBIT_DIM_FlewTo = 0xA82,                          /* table 2; hint 281; ref snowmines/Landed_Arwi Visible */
    GAMEBIT_WarpStoneUnlockedCC = 0xABA,                 /* table 1; Unused feature where WarpStone would send you to more places. Setting these bits enables an invisble destination menu, b */
    GAMEBIT_WarpStoneUnlockedOFP = 0xABD,                /* table 1 */
    GAMEBIT_WarpStoneUnlockedLV = 0xABE,                 /* table 1 */
    GAMEBIT_WarpStoneUnlockedMMP = 0xABF,                /* table 1 */
    GAMEBIT_WarpStoneUnlockedVFP = 0xAC0,                /* table 1 */
    GAMEBIT_WarpStoneUnlockedIM = 0xAC1,                 /* table 1 */
    GAMEBIT_WM_Unk0AC8 = 0xAC8,                          /* table 0; set on first visit to Krazoa Palace */
    GAMEBIT_SHOP_Unk0AD3 = 0xAD3,                        /* table 2; set when entering shop */
    GAMEBIT_ITEM_WMGoldKey_Used = 0xADA,                 /* table 2; ref warlock/WM_padlock 0x1C */
    GAMEBIT_SawBarrelGen = 0xADB,                        /* table 2 */
    GAMEBIT_IM_CannonGuy1Dead = 0xADC,                   /* table 2 */
    GAMEBIT_IM_CannonGuy2Dead = 0xADD,                   /* table 2 */
    GAMEBIT_IM_SwitchVisible = 0xADE,                    /* table 0 */
    GAMEBIT_ITEM_CCGoldBar_Count = 0xAF7,                /* table 2; size 3 */
    GAMEBIT_CFRelated0B2A = 0xB2A,                       /* table 1 */
    GAMEBIT_CFRelated0B2B = 0xB2B,                       /* table 1 */
    GAMEBIT_CFRelated0B2C = 0xB2C,                       /* table 1 */
    GAMEBIT_CFRelated0B2D = 0xB2D,                       /* table 1 */
    GAMEBIT_CFRelated0B2E = 0xB2E,                       /* table 1 */
    GAMEBIT_CFRelated0B2F = 0xB2F,                       /* table 1 */
    GAMEBIT_CFRelated0B30 = 0xB30,                       /* table 1 */
    GAMEBIT_CFRelated0B31 = 0xB31,                       /* table 1 */
    GAMEBIT_CFRelated0B32 = 0xB32,                       /* table 1 */
    GAMEBIT_CFRelated0B37 = 0xB37,                       /* table 1 */
    GAMEBIT_CFRelated0B38 = 0xB38,                       /* table 1 */
    GAMEBIT_CFRelated0B39 = 0xB39,                       /* table 1 */
    GAMEBIT_CFRelated0B3A = 0xB3A,                       /* table 1 */
    GAMEBIT_CFRelated0B3B = 0xB3B,                       /* table 1 */
    GAMEBIT_CFRelated0B3C = 0xB3C,                       /* table 1 */
    GAMEBIT_CFRelated0B3D = 0xB3D,                       /* table 1 */
    GAMEBIT_CFRelated0B3E = 0xB3E,                       /* table 1 */
    GAMEBIT_CFRelated0B3F = 0xB3F,                       /* table 1 */
    GAMEBIT_CFRelated0B46 = 0xB46,                       /* table 1; ref fortress/CNTstopwatc enabled */
    GAMEBIT_CFRelated0B6C = 0xB6C,                       /* table 1 */
    GAMEBIT_LINKA_ActNo = 0xB81,                         /* table 1; size 4 */
    GAMEBIT_CF_DeathGasActive = 0xB97,                   /* table 1; ref fortress/deathGasNoF active */
    GAMEBIT_ITEM_BombSpore_ShowCount = 0xB98,            /* table 2; on HUD */
    GAMEBIT_ITEM_TrickyFood_ShowCount = 0xB99,           /* table 2 */
    GAMEBIT_ITEM_Firefly_ShowCount = 0xB9A,              /* table 2 */
    GAMEBIT_ITEM_MoonSeed_ShowCount = 0xB9B,             /* table 2 */
    GAMEBIT_ITEM_Scarab_ShowCount = 0xB9C,               /* table 2 */
    GAMEBIT_ECSH_TestObservRunning = 0xB9D,              /* table 0; ref ecshrine/HitAnimator target */
    GAMEBIT_ECSH_Entered = 0xBA5,                        /* table 1; hint 248; Krystal entered shrine */
    GAMEBIT_LINKI_ActNo = 0xBC7,                         /* table 0; This seems wrong... */
    GAMEBIT_ITEM_LVBlock3_Used = 0xBDE,                  /* table 2; ref swapcircle/SC_blockpla open */
    GAMEBIT_ITEM_LVBlock1_Used = 0xBE5,                  /* table 2; ref swapcircle/SC_blockpla open */
    GAMEBIT_IM_Unk0BEB = 0xBEB,                          /* table 0; set when first entering */
    GAMEBIT_IM_Unk0BEC = 0xBEC,                          /* table 0; set when first entering */
    GAMEBIT_IM_Unk0BED = 0xBED,                          /* table 0; set when first entering */
    GAMEBIT_IM_Unk0BEE = 0xBEE,                          /* table 0; set when first entering */
    GAMEBIT_IM_Unk0BEF = 0xBEF,                          /* table 0; set when first entering */
    GAMEBIT_SH_initObjGroups = 0xBF8,                    /* table 0 */
    GAMEBIT_ITEM_TestCombatSpirit_Got = 0xBFD,           /* table 2; hint 312 */
    GAMEBIT_MaybeHaveTricky = 0xC11,                     /* table 2; maybe wrong */
    GAMEBIT_DIM_CannonRelated0C17 = 0xC17,               /* table 2; related to DIM cannon */
    GAMEBIT_ITEM_LVBlock1_Got = 0xC25,                   /* table 2; ref swapcircle/SC_blockpla key */
    GAMEBIT_ITEM_LVBlock2_Got = 0xC26,                   /* table 2; ref swapcircle/SC_blockpla key */
    GAMEBIT_ITEM_LVBlock3_Got = 0xC27,                   /* table 2; ref swapcircle/SC_blockpla key */
    GAMEBIT_CannonRelated0C2D = 0xC2D,                   /* table 2 */
    GAMEBIT_CannonRelated0C2E = 0xC2E,                   /* table 2 */
    GAMEBIT_PlayerIsDisguised = 0xC30,                   /* table 0 */
    GAMEBIT_ITEM_SuperQuake_Got = 0xC55,                 /* table 2; hint 364; ref wallcity/MagicCaveTo Collected */
    GAMEBIT_ITEM_Viewfinder_Got = 0xC64,                 /* table 2; hint 409; aka High-Defnition Display Device or Zoom Goggles */
    GAMEBIT_ITEM_SpiritTestStrength_Got = 0xC6E,         /* table 2; hint 380 */
    GAMEBIT_ITEM_Spirit4_Used = 0xC70,                   /* table 2; hint 382 */
    GAMEBIT_TransporterRelated07C1 = 0xC71,              /* table 2 */
    GAMEBIT_ITEM_RockCandy_Got = 0xC7C,                  /* table 2 */
    GAMEBIT_ITEM_RockCandy_Used = 0xC7D,                 /* table 2; hint 258 */
    GAMEBIT_SH_WarpStoneComplainingAboutGifts = 0xC7E,   /* table 2; triggers "nobody brings me gifts" scene */
    GAMEBIT_DFSH_ObjGroups = 0xC84,                      /* table 3; size 32 */
    GAMEBIT_ITEM_Spirit5_Got = 0xC85,                    /* table 2; hint 417 */
    GAMEBIT_LINKE_TunnelOpen = 0xC8B,                    /* table 2; broke open wind tunnel in LinkE */
    GAMEBIT_ITEM_PDA_Got = 0xC8D,                        /* table 2; Set when landing at TTH */
    GAMEBIT_Tricky_SaidGoodBye = 0xC92,                  /* table 2; hint 418 */
    GAMEBIT_ITEM_CCGoldBar1_NotReturned = 0xCA3,         /* table 2 */
    GAMEBIT_ITEM_CCGoldBar2_NotReturned = 0xCA4,         /* table 2 */
    GAMEBIT_ITEM_CCGoldBar3_NotReturned = 0xCA5,         /* table 2 */
    GAMEBIT_ITEM_CCGoldBar4_NotReturned = 0xCA6,         /* table 2 */
    GAMEBIT_IM_BombPlanted = 0xCB2,                      /* table 2; in front of cheat well cave */
    GAMEBIT_IM_OpenedCheatWell = 0xCB3,                  /* table 2; ref newicemount/HitAnimator target */
    GAMEBIT_IM_CheatWellCaveRelated0CB4 = 0xCB4,         /* table 2; ref newicemount/ExplodeWall onExplode */
    GAMEBIT_ITEM_Spirit5_Released = 0xCB5,               /* table 2; hint 420 */
    GAMEBIT_ITEM_Spirit6_Released = 0xCB7,               /* table 2; hint 423; hint: "Andross Revealed" */
    GAMEBIT_TransportedRelated0CB8 = 0xCB8,              /* table 2; related to transporter */
    GAMEBIT_ITEM_SpellStone_Disabled = 0xCBC,            /* table 2; dims them in the menu */
    GAMEBIT_SawFuelCell = 0xCBE,                         /* table 2 */
    GAMEBIT_SB_KrystalBoardedGalleon = 0xCBF,            /* table 0; hint 245 */
    GAMEBIT_SawBafomdad = 0xCC0,                         /* table 2 */
    GAMEBIT_GF_ActNo = 0xCC2,                            /* table 1; size 4 */
    GAMEBIT_GF_PepperTalking = 0xCC5,                    /* table 0 */
    GAMEBIT_StaffPowerupAnimRunning = 0xCCC,             /* table 0; set when collecting an upgrade */
    GAMEBIT_SH_ThornTailRelated0CD5 = 0xCD5,             /* table 2; probably "talked to guy who tells you to get a lantern" */
    GAMEBIT_SH_ThornTailRelated0CD6 = 0xCD6,             /* table 2 */
    GAMEBIT_NW_ReturnedTo = 0xCE1,                       /* table 2; hint 277 */
    GAMEBIT_SHOP_Unk0CEF = 0xCEF,                        /* table 0; set when entering shop, cleared when leaving */
    GAMEBIT_NoBallsAllowed = 0xD00,                      /* table 3; Disables/despawns Tricky's ball */
    GAMEBIT_SH_EnteredWell = 0xD06,                      /* table 2; hint 271 */
    GAMEBIT_NW_Key_Used = 0xD16,                         /* table 2; ref wastes/HitAnimator target */
    GAMEBIT_WMRelated0D1B = 0xD1B,                       /* table 1 */
    GAMEBIT_WMRelated0D1C = 0xD1C,                       /* table 1 */
    GAMEBIT_WMRelated0D1D = 0xD1D,                       /* table 1 */
    GAMEBIT_WMRelated0D1E = 0xD1E,                       /* table 1 */
    GAMEBIT_WMRelated0D1F = 0xD1F,                       /* table 1 */
    GAMEBIT_NW_Key_Got = 0xD20,                          /* table 2; hint 275; XXX which? hint is "Saved Queen EarthWalker" */
    GAMEBIT_SHOP_Unk0D21 = 0xD21,                        /* table 0; set when entering shop */
    GAMEBIT_WM_KrystalCrystalized = 0xD27,               /* table 1 */
    GAMEBIT_SawStaffBoostPad = 0xD2A,                    /* table 2; StaffActivated checks for this (hardcoded) in some case relating to sequences */
    GAMEBIT_SH_Related0D35 = 0xD35,                      /* table 3 */
    GAMEBIT_SH_Related0D36 = 0xD36,                      /* table 3 */
    GAMEBIT_WM_FlewTo = 0xD37,                           /* table 1; hint 419; ref warlock/HitAnimator target */
    GAMEBIT_LINKF_ObjGroups = 0xD38,                     /* table 3; size 32 */
    GAMEBIT_SH_BloopEventDone = 0xD39,                   /* table 2 */
    GAMEBIT_CFRestartPointRelated0D3D = 0xD3D,           /* table 1 */
    GAMEBIT_VFPLightRelated0D44 = 0xD44,                 /* table 3; ref temple/LGTDirectio 0x1E */
    GAMEBIT_WarpPointRelatedD53 = 0xD53,                 /* table 1 */
    GAMEBIT_OFP_Entered = 0xD67,                         /* table 2; hint 339; ref dfptop/HitAnimator target */
    GAMEBIT_VFP_Opened = 0xD69,                          /* table 2; hint 303 */
    GAMEBIT_OFPTOP_WarpEnabled = 0xD6C,                  /* table 2; hint 340; ref dfptop/Transporter enabled */
    GAMEBIT_VFPRelated0D72 = 0xD72,                      /* table 1 */
    GAMEBIT_CFRelated0D73 = 0xD73,                       /* table 2; Cleared when Arwing flies to CR Fort */
    GAMEBIT_LINKH_ObjGroups = 0xD75,                     /* table 3; size 32 */
    GAMEBIT_WC_MagicCaveVisible = 0xD7D,                 /* table 2; ref wallcity/MagicCaveTo Visible */
    GAMEBIT_NW_GotPastBribeClaw = 0xD83,                 /* table 2; hint 266 */
    GAMEBIT_ITEM_FuelCell_ShowCount = 0xD97,             /* table 2; on HUD */
    GAMEBIT_CFRelated0DB8 = 0xDB8,                       /* table 3 */
    GAMEBIT_VFP_OpenedPathTo = 0xDBF,                    /* table 2; hint 300; ref moonpass/HitAnimator target */
    GAMEBIT_CFRelated0DCA = 0xDCA,                       /* table 0 */
    GAMEBIT_CFRaceRelated0DCB = 0xDCB,                   /* table 0 */
    GAMEBIT_LINKD_ObjGroups = 0xDD1,                     /* table 3; size 32 */
    GAMEBIT_ITEM_CheatToken0_Got = 0xDDC,                /* table 2; Display Credits */
    GAMEBIT_ITEM_CheatToken3_Got = 0xDDD,                /* table 2; Dino Language */
    GAMEBIT_ITEM_CheatToken2_Got = 0xDDE,                /* table 2; Music Test */
    GAMEBIT_ITEM_CheatToken6_Got = 0xDDF,                /* table 2 */
    GAMEBIT_ITEM_CheatToken4_Got = 0xDE0,                /* table 2 */
    GAMEBIT_ITEM_CheatToken7_Got = 0xDE1,                /* table 2 */
    GAMEBIT_ITEM_CheatToken1_Got = 0xDE2,                /* table 2; Sepia Mode */
    GAMEBIT_ITEM_CheatToken5_Got = 0xDE3,                /* table 2 */
    GAMEBIT_ITEM_CheatToken8_Got = 0xDE4,                /* table 2; No corresponding UsedCheatToken8? doesn't show up in C menu */
    GAMEBIT_Cheat0_Credits_Unlocked = 0xDE5,             /* table 2; Display Credits */
    GAMEBIT_Cheat3_Dino_Unlocked = 0xDE6,                /* table 2; Dino Language */
    GAMEBIT_Cheat2_MusicTest_Unlocked = 0xDE7,           /* table 2; Music Test */
    GAMEBIT_Cheat6_Unlocked = 0xDE8,                     /* table 2 */
    GAMEBIT_Cheat4_Unlocked = 0xDE9,                     /* table 2 */
    GAMEBIT_Cheat7_Unlocked = 0xDEA,                     /* table 2 */
    GAMEBIT_Cheat1_Sepia_Unlocked = 0xDEB,               /* table 2; Sepia Mode */
    GAMEBIT_Cheat5_Unlocked = 0xDEC,                     /* table 2 */
    GAMEBIT_Cheat8_Unlocked = 0xDED,                     /* table 2 */
    GAMEBIT_CreditsRelated0DF6 = 0xDF6,                  /* table 0; Set on title screen when showing credits (maybe "should run credits"?) */
    GAMEBIT_SH_PushedSwitchInWell = 0xDFF,               /* table 2 */
    GAMEBIT_WC_MagicCaveRelated0E05 = 0xE05,             /* table 2; cleared when Arwing flies to Walled City */
    GAMEBIT_CFRelated0E1D = 0xE1D,                       /* table 3 */
    GAMEBIT_CFRelated0E23 = 0xE23,                       /* table 3 */
    GAMEBIT_OpenedSecondPathThroughTemple = 0xE25,       /* table 2; hint 371; ref temple/HitAnimator target */
    GAMEBIT_DR_Unk0E26 = 0xE26,                          /* table 3; toggled constantly in Dragon Rock */
    GAMEBIT_DR_RescuedEarthWalker = 0xE27,               /* table 2; hint 388 */
    GAMEBIT_DR_DestroyedRobots = 0xE3F,                  /* table 2; hint 390 */
    GAMEBIT_WM_KrystalRelated0E49 = 0xE49,               /* table 0; set when she looks around in the crystal */
    GAMEBIT_SH_Got6WhiteShrooms = 0xE5B,                 /* table 2; hint 274 */
    GAMEBIT_IM_DestroyedBox1 = 0xE5D,                    /* table 2; blocking cannon */
    GAMEBIT_IM_DestroyedBox2 = 0xE5E,                    /* table 2 */
    GAMEBIT_IM_DestroyedBox3 = 0xE5F,                    /* table 2 */
    GAMEBIT_IM_DestroyedBox4 = 0xE60,                    /* table 2 */
    GAMEBIT_IM_DestroyedBox5 = 0xE61,                    /* table 2 */
    GAMEBIT_IM_DestroyedBox6 = 0xE62,                    /* table 2 */
    GAMEBIT_IM_DestroyedBox7 = 0xE63,                    /* table 2 */
    GAMEBIT_IM_DestroyedBox8 = 0xE64,                    /* table 2 */
    GAMEBIT_IM_DestroyedBox9 = 0xE65,                    /* table 2 */
    GAMEBIT_IM_DestroyedBox10 = 0xE66,                   /* table 2 */
    GAMEBIT_IM_DestroyedBox11 = 0xE67,                   /* table 2 */
    GAMEBIT_IM_DestroyedBox12 = 0xE68,                   /* table 2 */
    GAMEBIT_IM_DestroyedBox13 = 0xE69,                   /* table 2 */
    GAMEBIT_IM_BikeRelated0E6A = 0xE6A,                  /* table 2; set when gaining control of bike */
    GAMEBIT_IM_BikeRelated0E6B = 0xE6B,                  /* table 2; set when gaining control of bike */
    GAMEBIT_SH_ReturnedToWarpStone = 0xE6F,              /* table 0; hint 313; Fox returned with first spirit */
    GAMEBIT_MMP_EnteredKrazoaShrine = 0xE70,             /* table 0; hint 311 */
    GAMEBIT_ArwingRelated0E74 = 0xE74,                   /* table 0 */
    GAMEBIT_DRArwingRelated0E7B = 0xE7B,                 /* table 2; cleared when Arwing flies to Dragon Rock */
    GAMEBIT_SH_EggEventRelated0E80 = 0xE80,              /* table 2 */
    GAMEBIT_ITEM_FuelCell_CantGet = 0xE97,               /* table 0; Used when currently collecting one */
    GAMEBIT_DR_ShutDownRobotShields = 0xE9C,             /* table 2; hint 389 */
    GAMEBIT_WM_DestroyedBox5 = 0xE9F,                    /* table 2; second set */
    GAMEBIT_WM_DestroyedBox6 = 0xEA0,                    /* table 2 */
    GAMEBIT_WC_EnteredShrine = 0xEA1,                    /* table 0; hint 413 */
    GAMEBIT_K6_Entered = 0xEA2,                          /* table 0; hint 421 */
    GAMEBIT_OFPBOT_StaffBoostEnabled = 0xEA5,            /* table 2; ref kraztest/StaffBoostP enabled */
    GAMEBIT_ToldGetSnowHornArtifact = 0xEA6,             /* table 0 */
    GAMEBIT_SH_Give200ScarabBag = 0xEA8,                 /* table 2; Triggers a respawn point save */
    GAMEBIT_SH_GiveMoonPassKey = 0xEA9,                  /* table 2; Triggers a respawn point save */
    GAMEBIT_ITEM_BadGuyAlert_Got = 0xEB0,                /* table 2; unused shop item */
    GAMEBIT_ITEM_Magic_Got = 0xEB1,                      /* table 2 */
    GAMEBIT_ITEM_BafomdadHolder_Got = 0xEB2,             /* table 2 */
    GAMEBIT_SH_Related0EB3 = 0xEB3,                      /* table 2 */
    GAMEBIT_ITEM_Flute_Disabled = 0xEB5,                 /* table 2 */
    GAMEBIT_ECSH_CameraLookingAtDoor = 0xECA,            /* table 2; focuses camera on door */
    GAMEBIT_NW_EscapedFromSnowClearing = 0xECC,          /* table 0; hint 265 */
    GAMEBIT_VFP_Entered = 0xECE,                         /* table 0; hint 301 */
    GAMEBIT_FoundSpellStoneWarpPad_0ECF = 0xECF,         /* table 0; hint 304 */
    GAMEBIT_OFP_FoundSpellStoneWarpPad = 0xED0,          /* table 0; hint 341 */
    GAMEBIT_DR_OnCloudRunner = 0xED7,                    /* table 0 */
    GAMEBIT_SH_Related0EDE = 0xEDE,                      /* table 2; Triggers a communication after pushing switch at bottom of well */
    GAMEBIT_ITEM_SnowHornArtifactEE5 = 0xEE5,            /* table 2; set when using artifact */
    GAMEBIT_ITEM_SnowHornArtifactEE6 = 0xEE6,            /* table 2; set when using artifact */
    GAMEBIT_ECSH_InShrine = 0xEFA,                       /* table 0; set when entering Krazoa test 1, cleared when leaving */
    GAMEBIT_WarpRelated0EFB = 0xEFB,                     /* table 0; related to warp pads/magic cave; maybe override destination with MagicCaveExitWarp? */
    GAMEBIT_MAZEWELL_ACTIVE = 0xEFC,                     /* table 0; Music_Trigger(0x36) + Well active/hitbox state */
    GAMEBIT_PlayerInShop = 0xEFE,                        /* table 0 */
    GAMEBIT_LV_LocatedKrazoaShrine = 0xF07,              /* table 0; hint 351 */
    GAMEBIT_NW_DidPadHornTest = 0xF08,                   /* table 0; hint 379 */
    GAMEBIT_MapBits = 0xF10,                             /* table 2; up to F1C? */
    GAMEBIT_IM_Unk0F12 = 0xF12,                          /* table 2; set when first entering */
    GAMEBIT_TitleScreenRelated0F15 = 0xF15,              /* table 2; set at some point on file select */
    GAMEBIT_ArwingRelated0F16 = 0xF16,                   /* table 2; set in 1st Arwing level - if cleared, immediately sets again */
    GAMEBIT_SB_CanShootPropeller = 0xF1E,                /* table 0 */
    GAMEBIT_ITEM_CheatToken0_Used = 0xF34,               /* table 2; Display Credits */
    GAMEBIT_ITEM_CheatToken3_Used = 0xF35,               /* table 2; Dino Language */
    GAMEBIT_ITEM_CheatToken2_Used = 0xF36,               /* table 2; Music Test */
    GAMEBIT_ITEM_CheatToken6_Used = 0xF37,               /* table 2 */
    GAMEBIT_ITEM_CheatToken4_Used = 0xF38,               /* table 2 */
    GAMEBIT_ITEM_CheatToken7_Used = 0xF39,               /* table 2 */
    GAMEBIT_ITEM_CheatToken1_Used = 0xF3A,               /* table 2; Sepia Mode */
    GAMEBIT_ITEM_CheatToken5_Used = 0xF3B,               /* table 2 */
    GAMEBIT_SH_ToldGetViewFinder = 0xF3E,                /* table 2; Set when arriving after getting 4th stone; triggers a communication if you don't have viewfinder */
    GAMEBIT_WM_Warp3Enabled = 0xF43,                     /* table 2; ref warlock/Transporter enabled */
    GAMEBIT_WM_Warp4Enabled = 0xF44,                     /* table 2; ref warlock/Transporter enabled */
    GAMEBIT_WM_SwitchDoorOpen = 0xF45,                   /* table 2; pressure switch is pressed (resets automatically) */
    GAMEBIT_WM_SwitchRelated0F47 = 0xF47                 /* table 2; related to KP pressure-switch door */
};


/* extern-cleanup: consolidated prototypes (true-def sigs) */
void hudFn_8011f6f0(u8 x);
void hudDrawMagicBar(int alpha, int unk2, u32 flags);

#endif /* MAIN_GAMEBITS_H_ */
