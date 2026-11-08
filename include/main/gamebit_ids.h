#ifndef MAIN_GAMEBIT_IDS_H_
#define MAIN_GAMEBIT_IDS_H_

/*
 * GameBitId - symbolic ids for the game's persistent quest/story/event flags,
 * the integer `eventId` passed to mainGetBit / mainSetBits / gameBitIncrement /
 * gameBitDecrement, and to GameBitLatch_Update's three bit arguments.
 *
 * No bare bit id is left anywhere in src/: every one of those call sites, every
 * bit id assigned into a *gameBit* struct field, and every gamebit lookup table
 * names the bit it touches. Keep it that way - when a new id turns up, name it
 * here rather than spelling it as a literal, and do not add a second name for a
 * bit that already has one, since two DLLs disagreeing about one id is how the
 * worst mistakes in here got made.
 *
 * ONLY add an entry once the bit's meaning is established, and say in the
 * comment what established it. The evidence ladder, strongest first: the code
 * that writes it; a gametext label the game itself shows for it; Rena's map
 * objrefs (which map, which object, which param); adjacency to a named group.
 * Where only the weakest rung applies the name says so - Related, or an id
 * suffix - and where two sources conflict the comment says CAUTION rather than
 * picking a winner. A name that overstates what is known is worse than a hex
 * literal.
 *
 * Coverage: of the 3920 bit descriptors the game defines, every one with any
 * evidence at all is named. The rest have no code reference, no map objref, no
 * hint text and no entry in any of Rena's four name sets, so there is presently
 * nothing to derive them from - they are reachable only from map or script data
 * this project cannot yet read.
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
     * crosses it; ecshShrine_update polls it once and, the first frame it sees
     * it set, plays the "You have found your way into a KRAZOA SHRINE..."
     * NPC dialogue (0x285), latching ECSHShrineState.introTextLatch so it never
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
     * intro sequence; set by SpiritDoorLock_update. This bit is actually
     * GENERIC: SpiritDoorLock_update (dll_0167) uses this one hard-coded id
     * for ANY SpiritDoorLock, so it is a global "first
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
     * Krazoa Shrine return transporter pad (slot 300, base.ident 0x43F83 ->
     * map 0x21): once the spirit is taken, the pad locks out. Live-verified
     * that setting this disable path kills the pad's A-prompt.
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
     * r28 == 0x316*4 and the wmspiritplace object in r27). Read directly by
     * Transporter.c - one of the three 0xBA8/0x316/0x511
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
    GAMEBIT_WORLDMAP_OPEN = 0xA63,                       /* WORLDplanet names the same bit its world-map-open bit */

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
     * caught mainSetBits(0x2d, 1) in mcupgrade_update on collection. You use the
     * ability immediately on the reward-room exit switch below, then return and
     * shoot the separate red switch that opens the SharpClaw/Queen door.
     */
    GAMEBIT_STAFF_ABILITY_FIRE_BLASTER = 0x2D,           /* Backs the staff ability C-menu entry the game labels "Fire Blaster" (its owned bit) */

    /*
     * Fire Blaster reward-room exit gate. This bit is set while the iron gate is
     * closed. ProjectileSwitch stores its inverted form (0x8246), so shooting the
     * red switch turns it green, clears this underlying bit, and opens the gate.
     * Live-verified against the gate and switch in the first Magic Cave.
     */
    GAMEBIT_FIRE_BLASTER_MAGIC_CAVE_DOOR_CLOSED = 0x246,
    GAMEBIT_FIRE_BLASTER_MAGIC_CAVE_DOOR_CLOSED_LATCH = 0x28A,

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
    GAMEBIT_STAFF_ABILITY_FREEZE_BLAST       = 0x5CE,    /* freezes / puts out fires. Backs the staff ability C-menu entry the game labels "Freeze Blast" (its owned bit) */
    GAMEBIT_STAFF_ABILITY_SHARPCLAW_DISGUISE = 0x40,     /* enemies stop targeting you. Backs the staff ability C-menu entry the game labels "SharpClaw Disguise" (its owned bit) */
    GAMEBIT_STAFF_ABILITY_GROUND_QUAKE       = 0x107,    /* hidden once Super Quake is set. Backs the staff ability C-menu entry the game labels "Ground Quake" (its owned bit) */
    GAMEBIT_STAFF_ABILITY_SUPER_QUAKE        = 0xC55,    /* upgrade; replaces Ground Quake. Backs the staff ability C-menu entry the game labels "Ground Quake" (its used bit); and the staff ability C-menu entry the game labels "Super Quake" (its owned bit) */
    GAMEBIT_STAFF_ABILITY_OPEN_PORTAL        = 0x5BD,    /* opens the large square doors. Backs the staff ability C-menu entry the game labels "Open Portal" (its owned bit) */
    GAMEBIT_STAFF_ABILITY_STAFF_BOOSTER      = 0x957,    /* boost pads reach high ledges. Backs the staff ability C-menu entry the game labels "Staff Booster" (its owned bit) */

    /* ======================================================================
     * Originally imported from Rena Kunisaki's SFA research
     * (data/U0/gamebits.xml in github.com/RenaKunisaki/StarFoxAdventures), then
     * extended with names and notes recovered from this project's code. Rena's
     * names are NOT independently verified here; treat them as leads, not
     * ground truth. Four of Rena's sets were mined, not one: SFA-Browser's U0
     * (1041 names, against the 713 in the StarFoxAdventures copy this section
     * was first built from), SFA-Browser's K0 kiosk set, and SFA-Amethyst's
     * gamebits.h. The kiosk ids were checked before use: of 709 ids named in
     * both it and U0, 548 names match and every one of the 161 differences is a
     * prefix rename (SH_ to TTH_), never a change of meaning. The value is the global mainGetBit id (xml id, confirmed to
     * match this enum on known bits). Unordered - chronological activation
     * position is unknown. Ids already named above are omitted (their verified
     * names take precedence).
     * ====================================================================== */
    GAMEBIT_AndrossRelated0001 = 0x1,                    /* table 0; set when Andross's brain is defeated */
    GAMEBIT_AndrossRelated0002 = 0x2,                    /* table 0; polled before Andross's post-fight warp */
    GAMEBIT_AndrossRelated0003 = 0x3,                    /* table 0; polled before Andross's post-fight warp */
    GAMEBIT_AndrossRelated0004 = 0x4,                    /* table 0; polled before Andross's post-fight warp */
    GAMEBIT_SH_KilledBloop1 = 0x5,                       /* table 1 */
    GAMEBIT_WBCounter0006 = 0x6,                         /* Read out of the retail placement data: snowmines2/WB counterGameBit x1; dfshrine/Firebat counterGameBit x1. The field is called a counter but BITTABLE gives the id a width of 1, so it holds a flag - most likely "this one has been killed" rather than a tally */
    GAMEBIT_CF_CurveRequired0007 = 0x7,                  /* A curve-node gate read from the retail romlist: fortress requiredBit x4. RomCurveDef puts requiredBit at 0x30 and forbiddenBit at 0x32, and the path search only walks a node when its required bit is set and its forbidden bit is clear. Only curve variants whose layout is corroborated were read - the 0x34/type-36 nodes are 88% ids already named from other evidence with nothing out of range, whereas the 0x44/type-38 variant is 63% out of range there and was left alone */
    GAMEBIT_SH_KilledBloop2 = 0x8,                       /* table 1 */
    GAMEBIT_CC_LightFootEncounterTriggered = 0x9,        /* The DLL names this one itself: CC_LIGHTFOOT_ENCOUNTER_TRIGGERED_GAMEBIT in CClightfoot.c */
    GAMEBIT_NW_GeyserDisable = 0xA,                      /* The DLL names this one itself: NW_GEYSER_DISABLE_GAMEBIT in NW_geyser.c */
    GAMEBIT_SH_TalkedToPepper = 0xB,                     /* table 2; when first landing there */
    GAMEBIT_AndrossRelated000D = 0xD,                    /* table 0; toggled by Andross attack states */
    GAMEBIT_AndrossRelated000E = 0xE,                    /* table 0; set during Andross's phase-five transition */
    GAMEBIT_AndrossRelated000F = 0xF,                    /* table 0; set when Andross's missile attack timer expires */
    GAMEBIT_AndrossRelated0010 = 0x10,                   /* table 0; polled and cleared by Andross attack states */
    GAMEBIT_AndrossRelated0012 = 0x12,                   /* table 0 */
    GAMEBIT_SH_KilledBloop3 = 0x13,                      /* table 1 */
    GAMEBIT_SH_KilledBloop4 = 0x14,                      /* table 1 */
    GAMEBIT_OFT_SharpclawCoCounter0015 = 0x15,           /* Read out of the retail placement data: dfptop/sharpclawCo counterGameBit x1. The field is called a counter but BITTABLE gives the id a width of 1, so it holds a flag - most likely "this one has been killed" rather than a tally */
    GAMEBIT_DIM_HitAnimTarget0016 = 0x16,                /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/DIMSeqObjec objId= param=bit18; snowmines/HitAnimator objId= param=target; snowmines/HitAnimator objId= param=target (+2 more); table 1 */
    GAMEBIT_DIM_BossDefeatStateB0017 = 0x17,             /* Two DarkIce DLLs name it and differently: DIM_Boss raises it as its defeat state B, and DIM_LevelCo reads it as one half of a compound condition. Both fit the boss going down, but nothing in the code proves that, so the id stays in the name */
    GAMEBIT_NW_ClimbOnSnowHorn = 0x18,                   /* table 0; climbing onto SnowHorn (will warp you to nearby one) */
    GAMEBIT_NW_ClimbOffSnowHorn = 0x19,                  /* table 0 */
    GAMEBIT_DIM_Open001A = 0x1A,                         /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/DIMUseObjec objId= param=open; table 2 */
    GAMEBIT_DIM_SeqUsed001B = 0x1B,                      /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/CAMERAnewse objId= param=usedBit; table 2 */
    GAMEBIT_DIM_SeqUsed001C = 0x1C,                      /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/CAMERAnewse objId= param=usedBit; table 2 */
    GAMEBIT_DIM_SeqUsed0020 = 0x20,                      /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/CAMERAnewse objId= param=usedBit; table 2 */
    GAMEBIT_PlayerPeriodicHitImmune = 0x21,              /* While set the player stops taking the repeating damage surface type 28 deals - the surface handler only runs its periodic-hit timer while this is clear */
    GAMEBIT_SH_FoundQueen = 0x22,                        /* table 2; hint 256 */
    GAMEBIT_SH_SouthCave_Opening = 0x23,                 /* table 2; ref hollow/HitAnimator target */
    GAMEBIT_CC_LevelControlMusicEA0024 = 0x24,           /* Two Cape Claw DLLs name it and differently: CClightfoot despawns its LightFoot encounter while it is set, and CClevcontro makes it the GameBitLatch condition for music 0xEA - one area state, read for two purposes */
    GAMEBIT_ITEM_TrickyBall_Bought = 0x25,               /* table 2 */
    GAMEBIT_NW_TreebridBit0026 = 0x26,                   /* Read out of the retail placement data: wastes/NW_treebrid gameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM_FoundInjuredSnowHorn = 0x27,             /* table 2; hint 284 */
    GAMEBIT_ITEM_AlpineRoot_028 = 0x28,                  /* table 2 */
    GAMEBIT_DIM_ReleasedSnowHorn = 0x2A,                 /* table 2; hint 283; ref snowmines/DIMSnowHornShackle open. Backs the collectable item C-menu entry the game labels "Use Shackle Key" (its used bit) */
    GAMEBIT_ITEM_DIMShackleKey_Got = 0x2B,               /* table 2; ref snowmines/DIMSnowHornShackle key. Backs the collectable item C-menu entry the game labels "Use Shackle Key" (its owned bit) */
    GAMEBIT_DoorF4InteractionEnable = 0x2C,              /* The DLL names this one itself: DOORF4_INTERACTION_ENABLE_GAMEBIT in 244.c */
    GAMEBIT_DIM_LogFireAnim = 0x2E,                      /* The DLL names this one itself: DIM_LOG_FIRE_ANIM_GAMEBIT in DIMLogFire.c */
    GAMEBIT_DIM_HitAnimTarget002F = 0x2F,                /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/HitAnimator objId= param=target; table 2 */
    GAMEBIT_DIM_HitAnimTarget0030 = 0x30,                /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/HitAnimator objId= param=target; table 2 */
    GAMEBIT_DIM_SeqBit1A0031 = 0x31,                     /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/DIMSeqObjec objId= param=bit1A; table 0 */
    GAMEBIT_DIM_SeqBit180032 = 0x32,                     /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/DIMSeqObjec objId= param=bit18; table 2 */
    GAMEBIT_DIM_HitAnimTarget0033 = 0x33,                /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/HitAnimator objId= param=target; snowmines/HitAnimator objId= param=target; table 2 */
    GAMEBIT_DIM_LavaBallTrigger0036 = 0x36,              /* Read out of the retail placement data: snowmines/DIMLavaBall triggerGameBit x1; snowmines/DIMLavaSmas gateGameBit x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM_SeqBit1A0037 = 0x37,                     /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/DIMSeqObjec objId= param=bit1A; table 0 */
    GAMEBIT_DIM_SeqBit180038 = 0x38,                     /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/DIMSeqObjec objId= param=bit18; table 2 */
    GAMEBIT_DIM2_SeqBit180039 = 0x39,                    /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines2/DIM2SeqObje objId= param=bit18; table 2 */
    GAMEBIT_DIMRelated003A = 0x3A,                       /* table 2 */
    GAMEBIT_DIM_LavaBallTriggeredLaunch003B = 0x3B,      /* Read out of the retail placement data: snowmines/DIMLavaBall triggeredLaunchGameBit x1; snowmines/DIMLavaSmas triggerGameBit x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM_LavaBallTrigger003C = 0x3C,              /* Read out of the retail placement data: snowmines/DIMLavaBall triggerGameBit x1; snowmines/DIMLavaSmas gateGameBit x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIMLavaBallTrigger003D = 0x3D,               /* Read out of the retail placement data: snowmines/DIMLavaBall triggerGameBit x1; snowmines/DIMLavaSmas gateGameBit x1; swapcircle/TrigCyl activate x1; 3 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CF_HitAnimTarget003E = 0x3E,                 /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/HitAnimator objId= param=target; table 1 */
    GAMEBIT_CF_EnteredFort = 0x41,                       /* table 1; hint 326 */
    GAMEBIT_CF_SeqBit1A0042 = 0x42,                      /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFseqobject objId= param=bit1A; table 0 */
    GAMEBIT_CF_SavedQueen = 0x43,                        /* table 2; hint 329; ref fortress/CFExplodeFl onExplode */
    GAMEBIT_ITEM_PrisonKey_Got = 0x44,                   /* table 1. Backs the collectable item C-menu entry the game labels "Use Prison Key" (its owned bit) */
    GAMEBIT_CF_Open0046 = 0x46,                          /* Named from map data alone - nothing in the code or in any name list mentions it: clouddungeon/CFPrisonDoo objId= param=open; table 1 */
    GAMEBIT_CF_Open0047 = 0x47,                          /* Named from map data alone - nothing in the code or in any name list mentions it: clouddungeon/CFPrisonDoo objId= param=open; table 1 */
    GAMEBIT_CF_GuardianFreed = 0x48,                     /* table 1; the caged CloudRunner guardian has broken out. CFGuardian reads the same bit as its prison guard standing down */
    GAMEBIT_CF_GuardianQuestState = 0x4B,                /* The DLL names this one itself: GAMEBIT_CFGUARDIAN_QUEST_STATE in CFGuardian.c */
    GAMEBIT_CF_HitAnimTarget004C = 0x4C,                 /* Named from map data alone - nothing in the code or in any name list mentions it: clouddungeon/HitAnimator objId= param=target; clouddungeon/StaffLeverO objId= param=activated; table 2 */
    GAMEBIT_CF_PrisonCageOpened = 0x4D,                  /* table 2; old CloudRunner's cage is open */
    GAMEBIT_CF_GuardianCageOpen = 0x4E,                  /* The DLL names this one itself: GAMEBIT_CFGUARDIAN_CAGE_OPEN in CFGuardian.c */
    GAMEBIT_CF_HitAnimTarget004F = 0x4F,                 /* Named from map data alone - nothing in the code or in any name list mentions it: clouddungeon/HitAnimator objId= param=target; clouddungeon/StaffLeverO objId= param=activated; table 2 */
    GAMEBIT_CF_UncleFlewOff = 0x50,                      /* Set once the old CloudRunner prisoner (cfprisonuncle) has flown off after his cage is opened; gates his own render/update, silences cfperch's squawk sequence, and flips cfprisonguard's alarm behavior */
    GAMEBIT_ITEM_CFRedCrystal_Got = 0x51,                /* table 2; power gems in CloudRunner Fortress. Backs the collectable item C-menu entry the game labels "Place Crystal" (its owned bit) */
    GAMEBIT_ITEM_CFGreenCrystal_Got = 0x52,              /* table 2. Backs the collectable item C-menu entry the game labels "Place Crystal" (its owned bit) */
    GAMEBIT_ITEM_CFBlueCrystal_Got = 0x53,               /* table 2. Backs the collectable item C-menu entry the game labels "Place Crystal" (its owned bit) */
    GAMEBIT_CF_RedPowerBasePowered = 0x54,               /* table 2; set when the red power gem is installed */
    GAMEBIT_CF_GreenPowerBasePowered = 0x55,             /* table 2; set when the green power gem is installed */
    GAMEBIT_CF_BluePowerBasePowered = 0x56,              /* table 2; set when the blue power gem is installed */
    GAMEBIT_CF_PowerOn = 0x57,                           /* table 2; hint 328; ref clouddungeon/StaffLeverT enabled */
    GAMEBIT_CF_WindLiftActivation0058 = 0x58,            /* Read out of the retail placement data: fortress/CFWindLift activationGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CF_WindLiftActivation0059 = 0x59,            /* Read out of the retail placement data: fortress/CFWindLift activationGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CF_WindLiftActivation005A = 0x5A,            /* Read out of the retail placement data: fortress/CFWindLift activationGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CF_LeverActivated005B = 0x5B,                /* Named from map data alone - nothing in the code or in any name list mentions it: clouddungeon/StaffLeverT objId= param=activated; table 2 */
    GAMEBIT_CF_LeverActivated005C = 0x5C,                /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/StaffLeverT objId= param=activated; fortress/StaffLeverT objId= param=activated; fortress/StaffLeverT objId= param=activated; table 2 */
    GAMEBIT_CF_LeverActivated005D = 0x5D,                /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/StaffLeverT objId= param=activated; fortress/StaffLeverT objId= param=activated; fortress/StaffLeverT objId= param=activated; table 2 */
    GAMEBIT_ITEM_CFPowerKey_Used = 0x5F,                 /* table 2; ref fortress/HitAnimator target */
    GAMEBIT_ITEM_CFPowerKey_Got = 0x60,                  /* table 2; ref fortress/CFPowerLock key. Backs the collectable item C-menu entry the game labels "Use Power Key" (its owned bit) */
    GAMEBIT_DRBOT_Param1A0064 = 0x64,                    /* Named from map data alone - nothing in the code or in any name list mentions it: dragbot/DR_LightBea objId= param=_1A; table 1 */
    GAMEBIT_BabyCloudRunnerAirMeter = 0x66,              /* The DLL names this one itself: BABYCLOUDRUNNER_AIR_METER_GAME_BIT in 332.c */
    GAMEBIT_CF_FXEmitDisable0068 = 0x68,                 /* Read out of the retail placement data: fortress/FXEmit disableGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_IM_SeqBit1A006D = 0x6D,                      /* Named from map data alone - nothing in the code or in any name list mentions it: newicemount/IMSeqObject objId= param=bit1A; table 2 */
    GAMEBIT_IM_TrickyRelated006E = 0x6E,                 /* table 2; set after Tricky landing scene */
    GAMEBIT_IM_TrickyRelated006F = 0x6F,                 /* table 2; set when entering hut */
    GAMEBIT_IM_RescuedTricky = 0x70,                     /* table 2; hint 261; set at start of bike scene */
    GAMEBIT_IM_RaceStarted = 0x72,                       /* table 2; set when the race actually starts */
    GAMEBIT_ITEM_Staff_Got = 0x75,                       /* table 1; clearing on Galleon restarts ship battle. CAUTION: SB_Galleon names the same bit its intro gate. Having the staff plausibly gates that intro, but the two readings have not been reconciled against the code */
    GAMEBIT_WM_Galleon_despawn = 0x78,                   /* table 2 */
    GAMEBIT_IM_StartRace = 0x79,                         /* table 1; setting starts the race scene */
    GAMEBIT_SC_TestPhaseOver007A = 0x7A,                 /* Swapcircle (the LightFoot totem circle) has left its test phase - while set, sc_levelcontrol raises GAMEBIT_SC_HitAnimTarget0085 at every opportunity; while clear it instead watches 0x627 and GAMEBIT_SC_TotemRunCompleted for GAMEBIT_LV_DoneTests */
    GAMEBIT_SC_Open007B = 0x7B,                          /* Named from map data alone - nothing in the code or in any name list mentions it: swapcircle/SC_settelme objId= param=open; table 2 */
    GAMEBIT_SC_SettelmeClosedLatch007C = 0x7C,           /* Read out of the retail placement data: swapcircle/SC_settelme closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SC_LevelControlTotemCombo1 = 0x7D,           /* The DLL names this one itself: SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_1 in 438_SC_levelcon.h */
    GAMEBIT_SC_LevelControlTotemCombo2 = 0x7E,           /* The DLL names this one itself: SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_2 in 438_SC_levelcon.h */
    GAMEBIT_SC_LevelControlTotemCombo3 = 0x7F,           /* The DLL names this one itself: SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_3 in 438_SC_levelcon.h */
    GAMEBIT_SC_LevelControlTotemComboComplete = 0x80,    /* The DLL names this one itself: SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_COMPLETE in SC_levelcon.c */
    GAMEBIT_LV_Totem1_Activated = 0x81,                  /* Rena's U0 dataset; table 2, corroborated by SC_totempol naming the same bit the totem pole's FRONT face */
    GAMEBIT_LV_Totem2_Activated = 0x82,                  /* Rena's U0 dataset; table 2, corroborated by SC_totempol naming the same bit the totem pole's LEFT face */
    GAMEBIT_LV_Totem3_Activated = 0x83,                  /* Rena's U0 dataset; table 2, corroborated by SC_totempol naming the same bit the totem pole's RIGHT face */
    GAMEBIT_LV_Totem4_Activated = 0x84,                  /* Rena's U0 dataset; table 2, corroborated by SC_totempol naming the same bit the totem pole's REAR face */
    GAMEBIT_SC_HitAnimTarget0085 = 0x85,                 /* Rena has it as the target of swapcircle's HitAnimator 0x4C837; sc_levelcontrol raises it whenever GAMEBIT_SC_TestPhaseOver007A is up and clears it as a timed totem run starts */
    GAMEBIT_SC_MounddooClosedLatch0086 = 0x86,           /* Read out of the retail placement data: swapcircle/SC_mounddoo closedLatchGameBit, its DoorPlacement's field at 0x1A. Restored after a too-blunt audit removed it - the struct fits its record and the slot was never in question */
    GAMEBIT_SC_LVBlock2Related0087 = 0x87,               /* One of the three bits sc_levelcontrol raises the moment GAMEBIT_ITEM_LVBlock2_Used is set */
    GAMEBIT_SH_WarpStonePathOpen = 0x88,                 /* table 2; did blow up wall leading to WarpStone */
    GAMEBIT_SC_SteppingClosedLatch0089 = 0x89,           /* Read out of the retail placement data: swapcircle/SC_stepping closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SH_SouthCave_BombPlanted = 0x8A,             /* table 2; ref hollow/BombPlant exists */
    GAMEBIT_SH_WarpStoneBombPlanted = 0x8B,              /* table 2; ref hollow/BombPlant exists */
    GAMEBIT_CampFireRelated008C = 0x8C,                  /* table 0; read once by CampFire at setup, purely to latch its own CAMPFIRE_STATE_FLAG_GAME_BIT_8C_SET */
    GAMEBIT_SH_HitAnimTarget008D = 0x8D,                 /* Named from map data alone - nothing in the code or in any name list mentions it: hollow/HitAnimator objId= param=target; hollow/SH_BombWall objId= param=exploded; table 2 */
    GAMEBIT_NW_AlpineroHide008E = 0x8E,                  /* Read out of the retail placement data: wastes/NW_alpinero hideGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_TTH_BombPlanted08F = 0x8F,                   /* Rena's U0 dataset; table 2 */
    GAMEBIT_SH_Related0090 = 0x90,                       /* table 2; ref hollow/HitAnimator target */
    GAMEBIT_DIM2_SideloadArming0091 = 0x91,              /* Read out of the retail placement data: snowmines2/sideload armingGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SH_KilledBloop5 = 0x92,                      /* table 1 */
    GAMEBIT_SH_KilledBloop6 = 0x93,                      /* table 1 */
    GAMEBIT_SH_TrickyTrigger = 0x94,                     /* The DLL names this one itself: SH_TRICKY_TRIGGER_GAMEBIT in SH_tricky.c */
    GAMEBIT_Always1 = 0x95,                              /* table 0; used for always-available shop items */
    GAMEBIT_Always0 = 0x96,                              /* table 0; used for never-available (unused) shop items */
    GAMEBIT_SH_HitAnimTarget0097 = 0x97,                 /* Named from map data alone - nothing in the code or in any name list mentions it: hollow/HitAnimator objId= param=target; hollow/SH_BombWall objId= param=exploded; table 2 */
    GAMEBIT_CC_DoorRequired0098 = 0x98,                  /* The bit doorf4 requires of its sequence-283 and 284 doors, the way its 193 and 196 doors require GAMEBIT_ITEM_PrisonKey_Got; Rena places it in capeclaw */
    GAMEBIT_SH_KilledBloop7 = 0x99,                      /* table 1 */
    GAMEBIT_Tricky_Learned_Distract = 0x9E,              /* table 2; DP names this Tricky_Learned_Distract; set by SH_queenear after the Queen EarthWalker accepts all required white grubtubs; gates Tricky's Baddie Alert/Distract prompt. CAUTION: DIM_Boss names the same bit its LightFoot snowball gate. Needing Tricky's distract for that would explain it, but nothing here proves the two are the same thing */
    GAMEBIT_SB_GalleonTransitionArmed = 0x9F,            /* SB_Galleon's protection minigame arms its transition with this; Rena's U0 name for it was NpcTalkRelated009F, which says nothing */
    GAMEBIT_SB_GalleonTransitionUsed = 0xA0,             /* The used half of GAMEBIT_SB_GalleonTransitionArmed's pair, per SB_Galleon's own alias */
    GAMEBIT_TTH_BombPlanted0A1 = 0xA1,                   /* Rena's U0 dataset; table 2 */
    GAMEBIT_CC_GasVentPuzzleComplete = 0xA3,             /* CCgasventCo calls it the puzzle-complete bit; Rena had it only as CC_SeqNeedBit0A3 */
    GAMEBIT_WM_GalleonRelated00A4 = 0xA4,                /* table 1 */
    GAMEBIT_CC_Currents1_Disable = 0xA6,                 /* Disables some water currents in Cape Claw when some switch is activated; Rena's U0 dataset; table 2 */
    GAMEBIT_WM_SwitchRelatedA7 = 0xA7,                   /* table 0; related to KP pressure switch door; toggled repeatedly during Krystal getting captured scene */
    GAMEBIT_NW_HitAnimTarget00A8 = 0xA8,                 /* Named from map data alone - nothing in the code or in any name list mentions it: wastes/HitAnimator objId= param=target; table 2 */
    GAMEBIT_ITEM_FireGem_Count = 0xA9,                   /* table 2; size 2. Backs the collectable item C-menu entry the game labels "Place Fire Gem" (its owned bit) */
    GAMEBIT_CC_PedestalSourceActivated = 0xAA,           /* The DLL names this one itself: CC_PEDESTAL_SOURCE_ACTIVATED_GAMEBIT in CCpedstal.c */
    GAMEBIT_CC_FireCrystHide00AC = 0xAC,                 /* Read out of the retail placement data: capeclaw/CCfireCryst hideGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CC_SeqUsed0AD = 0xAD,                        /* Rena's U0 dataset; table 2 */
    GAMEBIT_SH_KilledBloop8 = 0xAE,                      /* table 1 */
    GAMEBIT_SH_KilledBloop9 = 0xAF,                      /* table 1 */
    GAMEBIT_SH_KilledBloop10 = 0xB0,                     /* table 1 */
    GAMEBIT_WM_NpcHintPrereq00B1 = 0xB1,                 /* One of three bits DLL 0x200's NPC checks together: with the player out of magic, any one of them still clear sends the NPC down its sequence 1 instead of its sequence 2. Retail spells all three in decimal */
    GAMEBIT_WM_NpcHintPrereq00B2 = 0xB2,                 /* One of three bits DLL 0x200's NPC checks together: with the player out of magic, any one of them still clear sends the NPC down its sequence 1 instead of its sequence 2. Retail spells all three in decimal */
    GAMEBIT_WM_NpcHintPrereq00B3 = 0xB3,                 /* One of three bits DLL 0x200's NPC checks together: with the player out of magic, any one of them still clear sends the NPC down its sequence 1 instead of its sequence 2. Retail spells all three in decimal */
    GAMEBIT_ITEM_Unknown_Used = 0xB4,                    /* table 2; Item name is "Unknown". Backs the collectable item C-menu entry the game labels "Unknown" (its used bit) */
    GAMEBIT_SH_KilledBloop11 = 0xBE,                     /* table 1 */
    GAMEBIT_SH_ReturnedToQueen = 0xBF,                   /* table 2; hint 270; Talked to queen after bringing Tricky back from Ice Mountain */
    GAMEBIT_SH_Entered00C0 = 0xC0,                       /* table 0; also toggled when leaving queen cave, and in CRFort */
    GAMEBIT_ITEM_TrickyFood_Count = 0xC1,                /* table 2; size 4; Number of Tricky foods (GrubTub Fungus). Backs the collectable item C-menu entry the game labels "Feed to Tricky" (its owned bit) */
    GAMEBIT_ITEM_WhiteGrubTub_Used = 0xC2,               /* table 2; size 3 */
    GAMEBIT_SH_ReturnedToHollow = 0xC3,                  /* table 2; hint 267 */
    GAMEBIT_SH_KilledBloop13 = 0xC4,                     /* table 1 */
    GAMEBIT_SH_KilledBloop14 = 0xC5,                     /* table 1 */
    GAMEBIT_SH_KilledBloop15 = 0xC6,                     /* table 1 */
    GAMEBIT_ITEM_Unknown_Got = 0xC7,                     /* table 2; Item name is "Unknown". Backs the collectable item C-menu entry the game labels "Unknown" (its owned bit) */
    GAMEBIT_IM_OnBike = 0xC8,                            /* table 1; set when you can actually steer but also during the cutscene of "rescuing" Tricky */
    GAMEBIT_IM_SeqBit1A00C9 = 0xC9,                      /* Named from map data alone - nothing in the code or in any name list mentions it: newicemount/IMSeqObject objId= param=bit1A; table 2 */
    GAMEBIT_IM_SeqBit1800CA = 0xCA,                      /* Named from map data alone - nothing in the code or in any name list mentions it: newicemount/IMSeqObject objId= param=bit18; table 2 */
    GAMEBIT_IM_HudHidden00CB = 0xCB,                     /* Raised where IMIceMounta hides its HUD, the branch opposite the one that raises GAMEBIT_IM_BikeRelated0379 for the world map */
    GAMEBIT_SH_OpenedTunnelToWell = 0xCC,                /* table 2; ref hollow/HitAnimator target */
    GAMEBIT_IM_SeqBit1800CD = 0xCD,                      /* Named from map data alone - nothing in the code or in any name list mentions it: newicemount/IMSeqObject objId= param=bit18; newicemount3/IMSeqObject objId= param=bit18; table 2 */
    GAMEBIT_IMRelated00CE = 0xCE,                        /* table 2 */
    GAMEBIT_WM_GalleonRelated00D0 = 0xD0,                /* table 2 */
    GAMEBIT_WM_GalleonClearDoor = 0xD1,                  /* The DLL names this one itself: WM_GALLEON_GAMEBIT_CLEAR_DOOR in WM_Galleon.c */
    GAMEBIT_NW_ClawDead0D3 = 0xD3,                       /* Rena's U0 dataset; table 2 */
    GAMEBIT_SawCannonExplanation = 0xDB,                 /* table 2; Rena's U0 name - DIMCannon raises it the first time it explains itself and tests it to skip the explanation thereafter */
    GAMEBIT_DIM_LevelControlInitialDialogue = 0xDC,      /* The DLL names this one itself: DIM_LEVEL_CONTROL_INITIAL_DIALOGUE_GAMEBIT in DIM_LevelCo.c */
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
    GAMEBIT_SHBOT_Exists00EC = 0xEC,                     /* Named from map data alone - nothing in the code or in any name list mentions it: hollow2/BombPlant objId= param=exists; table 2 */
    GAMEBIT_IM_ActNo = 0xED,                             /* table 1; size 4; Ice Mountain, newicemount, newicemount2, newicemount3 */
    GAMEBIT_CC_ActNo = 0xEE,                             /* table 2; size 4; Cape Claw */
    GAMEBIT_DFSH_ActNo = 0xEF,                           /* table 1; size 4; dfshrine (Test of Combat) */
    GAMEBIT_AnimTest_ActNo = 0xF0,                       /* table 1; size 4 */
    GAMEBIT_CC_SeqNeedBit0F1 = 0xF1,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_DIM_SnowHornSeqPending00F3 = 0xF3,           /* The DarkIce SnowHorn latches its sequence-triggered flag on sight of this in its idle state */
    GAMEBIT_SHBOT_SHwhitemusBit00F4 = 0xF4,              /* Read out of the retail placement data: hollow2/SH_whitemus gameBitId x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SH_KilledBloop16 = 0xF5,                     /* table 1 */
    GAMEBIT_TestCombatClawAlive0F6 = 0xF6,               /* Rena's U0 dataset; table 0 */
    GAMEBIT_TestCombatClawAlive0F7 = 0xF7,               /* Rena's U0 dataset; table 0 */
    GAMEBIT_TestCombatClawAlive0F8 = 0xF8,               /* Rena's U0 dataset; table 0 */
    GAMEBIT_TestCombatClawAlive0F9 = 0xF9,               /* Rena's U0 dataset; table 0 */
    GAMEBIT_TestCombatClawAlive0FA = 0xFA,               /* Rena's U0 dataset; table 0 */
    GAMEBIT_TestCombatClawAlive0FB = 0xFB,               /* Rena's U0 dataset; table 0 */
    GAMEBIT_DFSH_ObjCreatorDroppedItem = 0xFC,           /* The DLL names this one itself: DFSH_OBJ_CREATOR_DROPPED_ITEM_GAME_BIT in DFSH_ObjCre.c */
    GAMEBIT_WGSH_warpEnabled0FD = 0xFD,                  /* table 0; Rena's U0 name, annotated there as belonging to an unused map - the Krazoa Test 1 controller latches it once in its COMPLETE phase */
    GAMEBIT_ITEM_SpiritTestFear_Got = 0xFF,              /* table 2; hint 355; have the Krazoa Spirit from Test of Fear (and haven't released it) */
    GAMEBIT_OFB_DFPObjCreaGameBitA0100 = 0x100,          /* Read out of the retail placement data: kraztest/DFP_ObjCrea gameBitA x2 */
    GAMEBIT_DR_CurveForbidden0101 = 0x101,               /* A curve-node gate read from the retail romlist: trexboss forbiddenBit x25. RomCurveDef puts requiredBit at 0x30 and forbiddenBit at 0x32, and the path search only walks a node when its required bit is set and its forbidden bit is clear. Only curve variants whose layout is corroborated were read - the 0x34/type-36 nodes are 88% ids already named from other evidence with nothing out of range, whereas the 0x44/type-38 variant is 63% out of range there and was left alone */
    GAMEBIT_NW_RescuedSnowHornGateKeeper = 0x102,        /* table 2; hint 279 */
    GAMEBIT_PushableSequence = 0x103,                    /* The DLL names this one itself: PUSHABLE_SEQUENCE_GAME_BIT in 239.c */
    GAMEBIT_SH_KilledBloop17 = 0x104,                    /* table 1 */
    GAMEBIT_ITEM_GroundQuake_Got = 0x107,                /* table 2; hint 308; ref moonpass/MagicCaveTo Collected. Backs the staff ability C-menu entry the game labels "Ground Quake" (its owned bit) */
    GAMEBIT_AndrossRelated0108 = 0x108,                  /* table 0; first of six random Andross hit-cue bits */
    GAMEBIT_AndrossRelated0109 = 0x109,                  /* table 0; random Andross hit-cue bit */
    GAMEBIT_AndrossRelated010A = 0x10A,                  /* table 0; random Andross hit-cue bit */
    GAMEBIT_AndrossRelated010B = 0x10B,                  /* table 0; random Andross hit-cue bit */
    GAMEBIT_AndrossRelated010C = 0x10C,                  /* table 0; random Andross hit-cue bit */
    GAMEBIT_AndrossRelated010D = 0x10D,                  /* table 0; random Andross hit-cue bit */
    GAMEBIT_NW_EnergyEggVisibility0111 = 0x111,          /* Read out of the retail placement data: wastes/EnergyEgg visibilityGameBit x1; wastes/GroundAnima sunkGameBit x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_NW_GroundAnimaSunk0112 = 0x112,              /* Read out of the retail placement data: wastes/GroundAnima sunkGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_NW_MagicCaveVisible = 0x113,                 /* table 2; ref wastes/MagicCaveTo Visible */
    GAMEBIT_NW_GroundAnimaSunk0114 = 0x114,              /* Read out of the retail placement data: wastes/GroundAnima sunkGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SH_KilledBloop18 = 0x115,                    /* table 1 */
    GAMEBIT_NW_AlpineroHide0116 = 0x116,                 /* Read out of the retail placement data: wastes/NW_alpinero hideGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_NW_FreedSnowHorn = 0x11A,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_NW_ClawDead120 = 0x120,                      /* table 2; Rena's U0 name - NW_mammoth tests it alongside GAMEBIT_NW_ClawDead121 */
    GAMEBIT_NW_ClawDead121 = 0x121,                      /* table 2; Rena's U0 name - the second SharpClaw NW_mammoth checks */
    GAMEBIT_TTH_SeqNeedBit122 = 0x122,                   /* Rena's U0 dataset; table 2 */
    GAMEBIT_ITEM_FireSpellStone1_Got = 0x123,            /* table 2; hint 297; ref temple/VFP_PodiumP key. Backs the collectable item C-menu entry the game labels "Use SpellStone" (its owned bit) */
    GAMEBIT_TTH_SeqUsedBit124 = 0x124,                   /* table 2; Rena's U0 name (ThornTail Hollow, the SH_ prefix these sources later renamed to TTH_) - read by SH_LevelCon */
    GAMEBIT_WM_KrazTest1Related0126 = 0x126,             /* Krazoa Test 1 - raised at init, on the test completing and on reset, and dropped where the controller releases its gfx handle after spawning its second effect */
    GAMEBIT_TestStrengthTexScrollRelated127 = 0x127,     /* table 0; Rena's U0 name - the Krazoa Test 1 controller raises it from an animation event and on each update, and clears it as the test completes */
    GAMEBIT_WM_KrazTest1Related0128 = 0x128,             /* Krazoa Test 1 - raised by the one anim event whose own #define is named for this bit, which also kicks the DLL's shader stub */
    GAMEBIT_WM_EnteredKrazoaTest1_0129 = 0x129,          /* table 0; set when entering Krazoa test 1, cleared when talking to spirit */
    GAMEBIT_MMSH_Shrine012A = 0x12A,                     /* The DLL names this one itself: MMSH_SHRINE_GAMEBIT_012A in MMSH_Shrine.c */
    GAMEBIT_SHRINE_SpiritGranted012B = 0x12B,            /* Shared across the Krazoa shrines rather than belonging to one: GPSH raises it as it grants its spirit, beside GAMEBIT_ITEM_Spirit5_Got, and MMSH clears it in its own reset - hence the SHRINE_ prefix it shares with GAMEBIT_SHRINE_MUSIC_LOCK. MMSH_Shrine has only a placeholder alias for it */
    GAMEBIT_CF_GCRobotPatrCounter012C = 0x12C,           /* Read out of the retail placement data: fortress/GCRobotPatr counterGameBit x13. The field is called a counter but BITTABLE gives the id a width of 1, so it holds a flag - most likely "this one has been killed" rather than a tally */
    GAMEBIT_MMSH_Shrine012D = 0x12D,                     /* The DLL names this one itself: MMSH_SHRINE_GAMEBIT_012D in MMSH_Shrine.c */
    GAMEBIT_ITEM_TrickyFood_GrabInProgress = 0x12E,      /* Global latch: set by dll_01A7 EdibleMushroom when a GrubTub Fungus offers itself to the player (grab in range), cleared once the grab-complete reply lands and TrickyFood_Count (or the romDefNo-0x658 variant's bit) increments; read by Tricky's food check as a stand-in for already owning TrickyFood */
    GAMEBIT_HintTexts0 = 0x12F,                          /* table 2; size 32; related to hint texts; flags, set when Krystal boards ship */
    GAMEBIT_HintTexts1 = 0x130,                          /* table 2; size 32 */
    GAMEBIT_HintTexts2 = 0x131,                          /* table 2; size 32 */
    GAMEBIT_HintTexts3 = 0x132,                          /* table 2; size 32 */
    GAMEBIT_HintTexts4 = 0x133,                          /* table 2; size 32 */
    GAMEBIT_HintTexts5 = 0x134,                          /* table 2; size 32 */
    GAMEBIT_HintTexts6 = 0x135,                          /* table 2; size 32 */
    GAMEBIT_HintTexts7 = 0x136,                          /* table 2; size 32 */
    GAMEBIT_CC_HitAnimTarget0138 = 0x138,                /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/HitAnimator objId= param=target; table 2 */
    GAMEBIT_ITEM_Firefly_Count = 0x13D,                  /* table 2; size 5. FireFly calls it collect-count bit A, agreeing that it is a count */
    GAMEBIT_ITEM_FireflyLantern_Got = 0x13E,             /* table 2; hint 273. Backs the collectable item C-menu entry the game labels "Use Lantern" (its owned bit) */
    GAMEBIT_ITEM_BigScarabBag_Got = 0x13F,               /* table 1; hint 375; From rescuing ThornTails from Bloops */
    GAMEBIT_SH_FirstMagicCaveFound = 0x140,              /* table 2; whether entrance is active (glowing, can enter) */
    GAMEBIT_CC_DIMCannonHold0142 = 0x142,                /* Read out of the retail placement data: capeclaw/DIMCannon holdGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_WM_Spirit1Related_0143 = 0x143,              /* table 0; set when collecting first spirit; cleared when it enters krazoa head */
    GAMEBIT_MC_ActNo = 0x144,                            /* table 1; size 4; Magic Cave */
    GAMEBIT_MC_ObjGroups = 0x145,                        /* table 3; size 32 */
    GAMEBIT_DIM_LavaBallTriggeredLaunch0147 = 0x147,     /* Read out of the retail placement data: snowmines/DIMLavaBall triggeredLaunchGameBit x1; snowmines/DIMLavaSmas triggerGameBit x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_GPSH_SpawnKnowledgeSymbols = 0x148,          /* Test of Knowledge symbol creator latch; GPSH_Shrine sets it when the puzzle starts and GPSH_ObjCre consumes it to spawn the six pickup symbols */
    GAMEBIT_GPSH_KnowledgeSymbol1Solved = 0x149,         /* Test of Knowledge symbol-solved bit; one of the six GPSH pickup symbols has been collected */
    GAMEBIT_GPSH_KnowledgeSymbol2Solved = 0x14A,         /* Test of Knowledge symbol-solved bit; one of the six GPSH pickup symbols has been collected */
    GAMEBIT_GPSH_KnowledgeSymbol3Solved = 0x14B,         /* Test of Knowledge symbol-solved bit; one of the six GPSH pickup symbols has been collected */
    GAMEBIT_GPSH_KnowledgeSymbol4Solved = 0x14C,         /* Test of Knowledge symbol-solved bit; one of the six GPSH pickup symbols has been collected */
    GAMEBIT_GPSH_KnowledgeSymbol5Solved = 0x14D,         /* Test of Knowledge symbol-solved bit; one of the six GPSH pickup symbols has been collected */
    GAMEBIT_GPSH_KnowledgeSymbol6Solved = 0x14E,         /* Test of Knowledge symbol-solved bit; one of the six GPSH pickup symbols has been collected */
    GAMEBIT_DIM_LavaBallState014F = 0x14F,               /* Read out of the retail placement data: snowmines/DIMLavaBall stateGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM_LavaBallState0150 = 0x150,               /* Read out of the retail placement data: snowmines/DIMLavaBall stateGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM_SeqBit180156 = 0x156,                    /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/DIMSeqObjec objId= param=bit18; table 2 */
    GAMEBIT_NW_HitAnimTarget0159 = 0x159,                /* Named from map data alone - nothing in the code or in any name list mentions it: wastes/HitAnimator objId= param=target; wastes/NW_seqobjec objId= param=needBit; wastes/HitAnimator objId= param=target; table 2 */
    GAMEBIT_SH_WarpStoneRelated015A = 0x15A,             /* table 2; set during intro speech */
    GAMEBIT_CC_UsedCannon = 0x15C,                       /* table 2; hint 402; Used cannon to open route to Ocean Force Point */
    GAMEBIT_CC_OnExplode015E = 0x15E,                    /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/ExplodePlan objId= param=onExplode; table 2 */
    GAMEBIT_DBSH_Shrine015F = 0x15F,                     /* The DLL names this one itself: DBSH_SHRINE_GAMEBIT_015F in DBSH_Shrine.c */
    GAMEBIT_CC_LevelControlCameraBlocked = 0x160,        /* CClevcontro calls it the camera-blocked bit; Rena had it only as CC_SeqUsedBit160 */
    GAMEBIT_CC_LevelControlGroup1EEnabled = 0x161,       /* The DLL names this one itself: CC_LEVEL_CONTROL_GROUP_1E_ENABLED_GAMEBIT in CClevcontro.c */
    GAMEBIT_OFP_Opened = 0x162,                          /* table 2; hint 338; ref capeclaw/HitAnimator target */
    GAMEBIT_CC_HitAnimTarget0163 = 0x163,                /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/CCskullDoor objId= param=open; capeclaw/HitAnimator objId= param=target; capeclaw/CCseqobj objId= param=usedBit (+1 more); table 2 */
    GAMEBIT_WMRelated0164 = 0x164,                       /* table 2; ref capeclaw/HitAnimator target */
    GAMEBIT_CC_XYZAnimatorCompletion0165 = 0x165,        /* Read out of the retail placement data: capeclaw/XYZAnimator completionGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SH_ThornTailRelated0168 = 0x168,             /* table 2 */
    GAMEBIT_DBSH_SymbolRiseComplete = 0x16A,             /* The DLL names this one itself: DBSH_GAMEBIT_SYMBOL_RISE_COMPLETE in 405_DBSH_Shrine.h */
    GAMEBIT_DBSH_SymbolSpinSucceeded = 0x16B,            /* The DLL names this one itself: DBSH_GAMEBIT_SYMBOL_SPIN_SUCCEEDED in 405_DBSH_Shrine.h */
    GAMEBIT_DBSH_SymbolSpinFailed = 0x16C,               /* The DLL names this one itself: DBSH_GAMEBIT_SYMBOL_SPIN_FAILED in 405_DBSH_Shrine.h */
    GAMEBIT_DIM_AlpineRoHide016D = 0x16D,                /* Read out of the retail placement data: snowmines/DIMAlpineRo hideGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM_AlpineRoHide016E = 0x16E,                /* Read out of the retail placement data: snowmines/DIMAlpineRo hideGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_ITEM_DIMAlpineRoot_16F = 0x16F,              /* table 2; ref snowmines/CNTColideOb 0x1E */
    GAMEBIT_ITEM_DIMAlpineRoot_Count = 0x170,            /* table 2; size 2. Backs the collectable item C-menu entry the game labels "Alpine Root" (its owned bit) */
    GAMEBIT_DIM_ClawDead172 = 0x172,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_CC_XYZAnimatorCompletion0173 = 0x173,        /* Read out of the retail placement data: capeclaw/XYZAnimator completionGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_ITEM_Spirit6_Got = 0x174,                    /* table 2; hint 422 */
    GAMEBIT_NWSH_SeqBit1A0175 = 0x175,                   /* Named from map data alone - nothing in the code or in any name list mentions it: nwshrine/NWSH_Seqobj objId= param=bit1A; table 0 */
    GAMEBIT_NWSH_SeqBit180176 = 0x176,                   /* Named from map data alone - nothing in the code or in any name list mentions it: nwshrine/NWSH_Seqobj objId= param=bit18; table 0 */
    GAMEBIT_SH_Related0177 = 0x177,                      /* table 2 */
    GAMEBIT_DIM_Lever17A = 0x17A,                        /* Rena's U0 dataset; table 2 */
    GAMEBIT_ITEM_DIMCog1_Got = 0x17B,                    /* table 2; ref snowmines/DIMUseObjec key. Backs the collectable item C-menu entry the game labels "Place Cog" (its owned bit) */
    GAMEBIT_DIM_BridgeRelated17C = 0x17C,                /* Rena's U0 dataset; table 2 */
    GAMEBIT_DIM_BridgeRelated17D = 0x17D,                /* Rena's U0 dataset; table 2 */
    GAMEBIT_ITEM_DIMCog2_Got = 0x17E,                    /* table 2; ref snowmines/TreasureChe item. Backs the collectable item C-menu entry the game labels "Place Cog" (its owned bit) */
    GAMEBIT_ITEM_DIMCog3_Got = 0x17F,                    /* table 2; ref snowmines/TreasureChe item. Backs the collectable item C-menu entry the game labels "Place Cog" (its owned bit) */
    GAMEBIT_ITEM_DIMCog4_Got = 0x180,                    /* table 2; ref snowmines/TreasureChe item. Backs the collectable item C-menu entry the game labels "Place Cog" (its owned bit) */
    GAMEBIT_ITEM_DIMCog1_Used = 0x181,                   /* table 2; ref snowmines/DIMUseObjec open. Backs the collectable item C-menu entry the game labels "Place Cog" (its used bit) */
    GAMEBIT_ITEM_DIMCog2_Used = 0x182,                   /* table 2; ref snowmines/DIMUseObjec open. Backs the collectable item C-menu entry the game labels "Place Cog" (its used bit) */
    GAMEBIT_ITEM_DIMCog3_Used = 0x183,                   /* table 2; ref snowmines/DIMUseObjec open. Backs the collectable item C-menu entry the game labels "Place Cog" (its used bit) */
    GAMEBIT_ITEM_DIMCog4_Used = 0x184,                   /* table 2; ref snowmines/DIMUseObjec open. Backs the collectable item C-menu entry the game labels "Place Cog" (its used bit) */
    GAMEBIT_Tricky_LoadBadge = 0x186,                    /* table 2 */
    GAMEBIT_IM_SnowRelated0188 = 0x188,                  /* table 2; set when you enter the trigger that starts the snow */
    GAMEBIT_SawBombPlant = 0x189,                        /* table 2 */
    GAMEBIT_TTH_BeaconRelated18C = 0x18C,                /* Rena's U0 dataset; table 2 */
    GAMEBIT_TTH_BeaconRelated18D = 0x18D,                /* Rena's U0 dataset; table 2 */
    GAMEBIT_SawBombSpore = 0x18E,                        /* table 2 */
    GAMEBIT_TTH_BeaconRelated18F = 0x18F,                /* Rena's U0 dataset; table 2 */
    GAMEBIT_SH_FireWeed_190 = 0x190,                     /* table 2 */
    GAMEBIT_SH_FireWeed_191 = 0x191,                     /* table 2 */
    GAMEBIT_SH_FireWeed_192 = 0x192,                     /* table 2 */
    GAMEBIT_ITEM_MoonPassKey_Got = 0x193,                /* table 2; hint 298 */
    GAMEBIT_ITEM_FireWeed_Count = 0x194,                 /* table 2; size 2. Backs the collectable item C-menu entry the game labels "Place Fire Weed" (its owned bit) */
    GAMEBIT_TumbleWeedPickup0195 = 0x195,                /* DLL 209 drops it into its own triggerGameBit as the player comes within range of a tumbleweed, then hands that field to the pickup message */
    GAMEBIT_SawBombPlantPatch = 0x196,                   /* table 2 */
    GAMEBIT_TTH_SeqNeedBit197 = 0x197,                   /* Rena's U0 dataset; table 2 */
    GAMEBIT_TTH_SeqUsedBit198 = 0x198,                   /* Rena's U0 dataset; table 2 */
    GAMEBIT_TTH_ThornTailTriggerAct7 = 0x199,            /* SHthorntail calls it its act-7 trigger, and SH_queenear reads it too; Rena had it only as TTH_SeqNeedBit199 */
    GAMEBIT_TTH_SeqNeedBit19A = 0x19A,                   /* Rena's U0 dataset; table 2 */
    GAMEBIT_SH_ReturnedAfter4thStone = 0x19C,            /* table 2; hint 408 */
    GAMEBIT_SnowHornArtifact19D = 0x19D,                 /* table 2; set when using artifact */
    GAMEBIT_CC_LevelControlMusicCD = 0x19E,              /* The DLL names this one itself: CC_LEVEL_CONTROL_MUSIC_CD_GAMEBIT in CClevcontro.c */
    GAMEBIT_SnowHornArtifact19F = 0x19F,                 /* table 2; checked when using artifact */
    GAMEBIT_SH_ThornTailRelated01A0 = 0x1A0,             /* table 2; related to ThornTail */
    GAMEBIT_SH_KilledBloop12 = 0x1A1,                    /* table 1 */
    GAMEBIT_ITEM_NWSnowHornArtifact_Got = 0x1A2,         /* table 2; hint 377. Backs the collectable item C-menu entry the game labels "Give Gift" (its owned bit) */
    GAMEBIT_ITEM_NWSnowHornArtifact_Used = 0x1A3,        /* table 2; hint 378. Backs the collectable item C-menu entry the game labels "Give Gift" (its used bit) */
    GAMEBIT_SH_OpenedPathToMagicCave2 = 0x1A4,           /* table 2; ref hollow/HitAnimator target */
    GAMEBIT_TTH_BombPlanted1A5 = 0x1A5,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_NW_MagicCaveCollected = 0x1A6,               /* table 2; ref wastes/MagicCaveTo Collected */
    GAMEBIT_MusicLatchClear01A7 = 0x1A7,                 /* A GameBitLatch clear-bit shared by two areas: DIM_LevelCo passes it as the clearIfSet of its MUSICTRIG_drako_1 latch, and drmusiccont as the clearIfSet of its 0xE5 latch, both paired with GAMEBIT_SH_Landed064B as the clearIfClear - so it carries no area prefix */
    GAMEBIT_SH_WarpStoneRelated01A8 = 0x1A8,             /* table 0; toggled when talking to WarpStone, and in CRFort */
    GAMEBIT_NW_SeqNeed01A9 = 0x1A9,                      /* Named from map data alone - nothing in the code or in any name list mentions it: wastes/NWSteppingS objId= param=needBit; wastes/StaffLeverO objId= param=activated; table 2 */
    GAMEBIT_NW_SeqUsed01AA = 0x1AA,                      /* Named from map data alone - nothing in the code or in any name list mentions it: wastes/NWSteppingS objId= param=usedBit; table 2 */
    GAMEBIT_SH_MetQueen = 0x1AB,                         /* table 2 */
    GAMEBIT_SH_SouthCave_Open = 0x1AC,                   /* table 2; ref hollow/SH_BombWall onExplode */
    GAMEBIT_PlantedBombSpore = 0x1AD,                    /* table 2; hint 257; ref hollow/SH_BombWall onExplode */
    GAMEBIT_SH_MagicCaveCollected = 0x1AE,               /* table 2; ref hollow/MagicCaveTo Collected */
    GAMEBIT_TTH_WallExploded1AF = 0x1AF,                 /* possibly triggers explosion; Rena's U0 dataset; table 2 */
    GAMEBIT_TTH_WallExploded1B0 = 0x1B0,                 /* Rena's U0 dataset; table 2 */
    GAMEBIT_SHBOT_XYZAnimatorCompletion01B1 = 0x1B1,     /* Read out of the retail placement data: hollow2/XYZAnimator completionGameBit x2; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_TTH_WallExploded1B2 = 0x1B2,                 /* Rena's U0 dataset; table 2 */
    GAMEBIT_CC_HitAnimTarget01B3 = 0x1B3,                /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/HitAnimator objId= param=target; table 0 */
    GAMEBIT_SH_BombPlantedBesideWarpStone = 0x1B4,       /* table 2; ref hollow/BombPlant exists */
    GAMEBIT_TTH_WallExploded1B5 = 0x1B5,                 /* Rena's U0 dataset; table 2 */
    GAMEBIT_CC_MagicCaveCollected = 0x1B6,               /* table 2; ref capeclaw/MagicCaveTo Collected */
    GAMEBIT_SH_CaveOpenedBesideWarpStone = 0x1B7,        /* table 2; ref hollow/HitAnimator target */
    GAMEBIT_MagicCaveExitWarp = 0x1B8,                   /* table 2; size 8; WARPTAB index that magic cave will exit to */
    GAMEBIT_IM_TrickyRelated01B9 = 0x1B9,                /* table 0; set when starting Tricky landing scene */
    GAMEBIT_MusicLatchClear01BA = 0x1BA,                 /* Another shared GameBitLatch clear-bit: DIM_LevelCo uses it as the clearIfSet of its day/night ambient latch, and IMIceMounta as the clearIfSet of a Tricky-state latch */
    GAMEBIT_NW_SomethingFreedFromIce = 0x1BB,            /* might be "ice breaking"; Rena's U0 dataset; table 2 */
    GAMEBIT_CC_SeqNeedBit1BC = 0x1BC,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_IM_SlippyWarnedCold = 0x1BD,                 /* table 2 */
    GAMEBIT_ITEM_GiveScarabs_Count = 0x1BE,              /* table 2; size 8; Money (in Give Scarabs option). Backs the collectable item C-menu entry the game labels "Give Scarabs" (its owned bit) */
    GAMEBIT_IM_TriggerSlippy = 0x1BF,                    /* table 2; Set to trigger Slippy's "water is cold" warning if not already seen */
    GAMEBIT_CC_GasVentActive = 0x1C0,                    /* The DLL names this one itself: CC_GAS_VENT_ACTIVE_GAMEBIT in 389_CCgasvent.h */
    GAMEBIT_CC_Open01C1 = 0x1C1,                         /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/CCprisonDoo objId= param=open; capeclaw/HitAnimator objId= param=target; table 2 */
    GAMEBIT_CC_QueenProximityLatch = 0x1C2,              /* The DLL names this one itself: CC_QUEEN_PROXIMITY_LATCH_GAMEBIT in CCqueen.c */
    GAMEBIT_ITEM_NWKey_Got2 = 0x1C3,                     /* table 2; hint 322 */
    GAMEBIT_CC_Located = 0x1C4,                          /* table 2; hint 317 */
    GAMEBIT_CC_SeqUsed01C5 = 0x1C5,                      /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/CCseqobj objId= param=usedBit; table 2 */
    GAMEBIT_NWSH_SeqBit1A01C6 = 0x1C6,                   /* Named from map data alone - nothing in the code or in any name list mentions it: nwshrine/NWSH_Seqobj objId= param=bit1A; table 0 */
    GAMEBIT_NWSH_SeqBit1801C7 = 0x1C7,                   /* Named from map data alone - nothing in the code or in any name list mentions it: nwshrine/NWSH_Seqobj objId= param=bit18; table 0 */
    GAMEBIT_BaddieRelated1C8 = 0x1C8,                    /* table 0 */
    GAMEBIT_PushableMagicGemNear = 0x1C9,                /* The DLL names this one itself: PUSHABLE_MAGIC_GEM_NEAR_GAME_BIT in 239.c */
    GAMEBIT_NWSH_Open01CA = 0x1CA,                       /* Named from map data alone - nothing in the code or in any name list mentions it: nwshrine/SC_settelme objId= param=open; table 0 */
    GAMEBIT_NWSH_SpiritDoorLDone01CB = 0x1CB,            /* Read out of the retail placement data: nwshrine/SpiritDoorL doneGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_Dll199Related01CD = 0x1CD,                   /* The DLL names this one itself: DLL199_GAMEBIT_01CD in 409.c */
    GAMEBIT_Dll19ADroppedItem = 0x1CE,                   /* DLL 0x19A calls it its dropped-item bit while DLL 0x199 only has a placeholder for it, so the name follows the DLL that knows what it is */
    GAMEBIT_Dll199Related01CF = 0x1CF,                   /* The DLL names this one itself: DLL199_GAMEBIT_01CF in 409.c */
    GAMEBIT_WM_KrazTest1Solved = 0x1D1,                  /* table 1; Krazoa Test 1 passed - DLL 414 raises it and the test controller's RESOLVE phase waits on it before brightening and going to its DONE phase */
    GAMEBIT_WM_KrazTest1AnimState01D2 = 0x1D2,           /* Krazoa Test 1 - driven purely from animation: two anim events exist to set and clear it (their #defines are named for this bit), and init, completion and reset all force it down */
    GAMEBIT_WM_KrazTest1TorchesActive = 0x1D3,           /* Krazoa Test 1 shrine-countdown active; set by dll_019B when the timer starts with no unlocks yet, read by dll_019C torch props to ignite; cleared on test failure */
    GAMEBIT_WM_KrazTest1TimedOut = 0x1D4,                /* Krazoa Test 1 - raised the moment the countdown reaches zero, alongside the timeout sequence, and cleared again on reset. DLL 412 reads it as its rearm bit, which follows from a timeout */
    GAMEBIT_WM_KrazTest1KeepSolved01D5 = 0x1D5,          /* Holds GAMEBIT_WM_KrazTest1Solved down: DLL 414 only clears the pass bit at the end of its sequence while this one is clear */
    GAMEBIT_IM_TrickyRelated01D6 = 0x1D6,                /* table 3; set when starting Tricky landing scene, cleared after race */
    GAMEBIT_ITEM_DeletedSpell1D7 = 0x1D7,                /* table 2; in spell bits table but does nothing */
    GAMEBIT_WM_KrazTest1TorchPulse = 0x1D8,              /* Krazoa Test 1 - a one-shot pulse the countdown phase consumes: seeing it raised bumps the controller's unlock count and clears it again, so it counts one torch at a time against GAMEBIT_WM_KrazTest1TorchesActive */
    GAMEBIT_CC_BridgeNeedBit = 0x1D9,                    /* table 2; Rena's U0 name - read by the wall-crawler DLL as an alternative to its proximity test, and by DFP_ForceAw. CAUTION: DLL 262 names the same bit its scarab burst-suppress, and DLL 529 and DFP_ForceAw read it too - three consumers with no shared reading established */
    GAMEBIT_CC_BridgeUsedBit = 0x1DA,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_DIM_SnowHornSeq4Triggered = 0x1DB,           /* Raised as the DarkIce SnowHorn's trigger case 4 puts it into trigger mode 9, and read back in two of its state handlers */
    GAMEBIT_DIM_SeqBit1801DC = 0x1DC,                    /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/DIMSeqObjec objId= param=bit18; table 2 */
    GAMEBIT_DIM_HitAnimTarget01DD = 0x1DD,               /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines3/HitAnimator objId= param=target; snowmines3/DIMSeqObjec objId= param=bit1A; table 1 */
    GAMEBIT_DIM_ReachedBoss = 0x1DF,                     /* table 1; hint 292 */
    GAMEBIT_DIM_HitAnimTarget01E0 = 0x1E0,               /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/HitAnimator objId= param=target; table 2 */
    GAMEBIT_DIM_HitAnimTarget01E1 = 0x1E1,               /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/HitAnimator objId= param=target; table 2 */
    GAMEBIT_DIM_CurveRequired01E2 = 0x1E2,               /* A curve-node gate read from the retail romlist: snowmines requiredBit x2. RomCurveDef puts requiredBit at 0x30 and forbiddenBit at 0x32, and the path search only walks a node when its required bit is set and its forbidden bit is clear. Only curve variants whose layout is corroborated were read - the 0x34/type-36 nodes are 88% ids already named from other evidence with nothing out of range, whereas the 0x44/type-38 variant is 63% out of range there and was left alone */
    GAMEBIT_DIM_Open01E3 = 0x1E3,                        /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/DIMLever objId= param=open; table 2 */
    GAMEBIT_DIM_BridgeRelated1E4 = 0x1E4,                /* Rena's U0 dataset; table 2 */
    GAMEBIT_DIM_LocatedCogs = 0x1E5,                     /* table 2; hint 287; ref snowmines/HitAnimator target */
    GAMEBIT_Dll199Related01E7 = 0x1E7,                   /* The DLL names this one itself: DLL199_GAMEBIT_01E7 in 409.c */
    GAMEBIT_DIM_MagicBridgeLatch = 0x1E8,                /* The DLL names this one itself: DIM_MAGIC_BRIDGE_GAMEBIT_LATCH in DIMMagicBri.c */
    GAMEBIT_DIM_MagicBridgeIgnited = 0x1E9,              /* The DLL names this one itself: DIM_MAGIC_BRIDGE_GAMEBIT_IGNITED in DIMMagicBri.c */
    GAMEBIT_CC_ClawDead1EA = 0x1EA,                      /* Rena's U0 dataset; table 2 */
    GAMEBIT_CC_ClawDead1EB = 0x1EB,                      /* Rena's U0 dataset; table 2 */
    GAMEBIT_CC_DIMCannonReset01EC = 0x1EC,               /* Read out of the retail placement data: capeclaw/DIMCannon resetGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_IM_TrickyRelated01ED = 0x1ED,                /* table 3; set when warping to Ice Mountain, cleared when starting Tricky landing scene */
    GAMEBIT_ITEM_DinoHorn_Got = 0x1EE,                   /* table 2; hint 288; ref snowmines/DIMUseObjec key. Backs the collectable item C-menu entry the game labels "Blow Horn" (its owned bit) */
    GAMEBIT_DIM_MagicBridgeTrigger = 0x1EF,              /* The DLL names this one itself: DIM_MAGIC_BRIDGE_GAMEBIT_TRIGGER in DIMMagicBri.c */
    GAMEBIT_Dll1D6HitEnable = 0x1F0,                     /* The DLL names this one itself: DLL1D6_HIT_ENABLE_GAMEBIT in 470.c */
    GAMEBIT_ITEM_DIM2CellKey_Got = 0x1F1,                /* table 2; ref snowmines2/DIM2CellKey key. Backs the collectable item C-menu entry the game labels "Use Gold Key" (its owned bit) */
    GAMEBIT_ITEM_DIMSilverKey_Got = 0x1F3,               /* table 2; ref snowmines2/DIM2CellKey key. Backs the collectable item C-menu entry the game labels "Use Silver Key" (its owned bit) */
    GAMEBIT_CF_Open01F8 = 0x1F8,                         /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFMainDoorA objId= param=open; table 2 */
    GAMEBIT_DIM_CrossedBlizzard = 0x1FA,                 /* table 2; hint 289 */
    GAMEBIT_SnowBikeRelated01FB = 0x1FB,                 /* table 2 */
    GAMEBIT_WM_FoundKrystal = 0x1FC,                     /* table 2; hint 315; Reached top of Krazoa Palace */
    GAMEBIT_LINKB_TrickyStateA = 0x1FD,                  /* Read by LINKB_levco at its stage 3 to jump straight to stage 4 */
    GAMEBIT_DIM_SeqBit1A01FE = 0x1FE,                    /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/DIMSeqObjec objId= param=bit1A; table 2 */
    GAMEBIT_LINKB_SeqBit180200 = 0x200,                  /* Named from map data alone - nothing in the code or in any name list mentions it: linkb/linkB_Stone objId= param=bit18; table 2 */
    GAMEBIT_ITEM_WCSunStone_Got = 0x201,                 /* table 2. Backs the collectable item C-menu entry the game labels "Use Sun Stone" (its owned bit) */
    GAMEBIT_ITEM_WCSunStone_Used = 0x202,                /* table 2. the sun temple DLL checks it as one of its four Walled City inventory bits, its C. Backs the collectable item C-menu entry the game labels "Use Sun Stone" (its used bit) */
    GAMEBIT_WC_TempleDiaBStage0 = 0x203,                 /* Walled City temple rotating-dial (bank B) - stage 0 complete, gWcTempleDiaGameBitsB[0]; bank chosen by ObjAnim.bankIndex != 0, otherwise as bank A */
    GAMEBIT_WC_TrexRunStart = 0x204,                     /* The last condition before the T-rex challenge starts: with the run requested, wclevelcont waits on this to clear the four lever bits and enter its TREX_INIT mode */
    GAMEBIT_WC_AllSwitchesActivated = 0x205,             /* Walled City - set by wclevelcont_updateAct2State once all three floor switches (0xC58/0xC59/0xC5A) read set; latches WCLEVELCTL_FLAG_SWITCHES and plays the confirm sfx */
    GAMEBIT_WC_TrexLever3Activated = 0x206,              /* One of the four wallcity staff levers the T-rex challenge runs on - wclevelcont raises all four at init and again when a run times out, and clears all four as a run starts; Rena records only a HitAnimator target (0x47FEF) for this one and no StaffLeverO, though the code writes it in lockstep with the other three everywhere */
    GAMEBIT_ITEM_DIM2CellKey_Used = 0x207,               /* table 2; ref snowmines2/DIM2CellKey open */
    GAMEBIT_ITEM_DIMSilverKey_Used = 0x208,              /* table 2; ref snowmines2/DIM2CellKey open */
    GAMEBIT_CF_MainDoorAClosedLatch0209 = 0x209,         /* Read out of the retail placement data: fortress/CFMainDoorA closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM2_IciclePhase1Win = 0x20B,                /* The DLL names this one itself: GAMEBIT_DIM2_ICICLE_PHASE1_WIN in DIM_Boss.c */
    GAMEBIT_DIM_BossTonsilHit = 0x20C,                   /* The DLL names this one itself: DIMBOSSTONSIL_HIT_GAMEBIT in 482_DIM_BossTon.h */
    GAMEBIT_DIM_BossIcicleDefeated = 0x20E,              /* The DLL names this one itself: DIMBOSS_GAMEBIT_ICICLE_DEFEATED in 480_DIM_Boss.h */
    GAMEBIT_DIM_BossRenderPause = 0x210,                 /* The DLL names this one itself: DIMBOSS_GAMEBIT_RENDER_PAUSE in DIM_Boss.c */
    GAMEBIT_CF_FlewTo = 0x212,                           /* table 1; hint 324 */
    GAMEBIT_CF_SeqBit180213 = 0x213,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFseqobject objId= param=bit18; fortress/CFseqobject objId= param=bit1A; table 2 */
    GAMEBIT_CF_SeqBit180214 = 0x214,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFseqobject objId= param=bit18; table 1 */
    GAMEBIT_DIM2_CellDooClosedLatch0215 = 0x215,         /* Read out of the retail placement data: snowmines2/DIM2CellDoo closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM2_CellDooClosedLatch0216 = 0x216,         /* Read out of the retail placement data: snowmines2/DIM2CellDoo closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM2_HitAnimTarget0218 = 0x218,              /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines2/HitAnimator objId= param=target; snowmines2/HitAnimator objId= param=target; table 2 */
    GAMEBIT_ITEM_DIMGoldKey_Used = 0x219,                /* table 2. Backs the collectable item C-menu entry the game labels "Use Gold Key" (its used bit) */
    GAMEBIT_ITEM_DIMSilverKey_Used_2 = 0x21A,            /* table 2. Backs the collectable item C-menu entry the game labels "Use Silver Key" (its used bit) */
    GAMEBIT_WM_CrystalRiseStage1 = 0x21B,                /* One step of the Warlock Mountain crystal's rise: WM_Crystal walks the whole chain every update and keeps the highest target any set bit asks for, this one raising it to 100 - wmsun_init raises it the moment Krazoa Palace reaches map act 3 */
    GAMEBIT_WM_CrystalRiseStage2 = 0x21C,                /* One step of the Warlock Mountain crystal's rise: WM_Crystal walks the whole chain every update and keeps the highest target any set bit asks for, this one raising it to 200 */
    GAMEBIT_WM_SpiritHead1Fired = 0x21D,                 /* table 1; when releasing spirit 1, head fired laser */
    GAMEBIT_WM_CrystalRiseStage4 = 0x21F,                /* One step of the Warlock Mountain crystal's rise: WM_Crystal walks the whole chain every update and keeps the highest target any set bit asks for, this one raising it to 800; stage 3 is GAMEBIT_WM_SpiritHead1Fired */
    GAMEBIT_WM_CrystalRiseStage5 = 0x221,                /* One step of the Warlock Mountain crystal's rise: WM_Crystal walks the whole chain every update and keeps the highest target any set bit asks for, this one raising it to 0x640 */
    GAMEBIT_WM_CrystalRiseStage6 = 0x222,                /* One step of the Warlock Mountain crystal's rise: WM_Crystal walks the whole chain every update and keeps the highest target any set bit asks for, this one raising it to 0x1900, and alone among them it triples the rise rate; once the crystal tops out on this stage it sets GAMEBIT_WM_FinaleQuakeActive */
    GAMEBIT_DIM_FoundBelinaTe = 0x223,                   /* table 2; hint 290 */
    GAMEBIT_MammothVariantZero0224 = 0x224,              /* Both DLLs that name it are mammoths - DIM2PrisonM calls it the variant-zero bit and NW_mammoth swaps its post-rescue gatekeeper onto an alternative trigger list while it is set - so the name drops either area's prefix; Rena has two snowmines2 HitAnimators targeting it */
    GAMEBIT_WC_SeqBit180225 = 0x225,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit18; table 2 */
    GAMEBIT_WC_TrexLever1Activated = 0x226,              /* One of the four wallcity staff levers the T-rex challenge runs on - wclevelcont raises all four at init and again when a run times out, and clears all four as a run starts; Rena has it as wallcity HitAnimator 0x47FED's target and StaffLeverO 0x4CB3D's activated param */
    GAMEBIT_CC_LeverActivated228 = 0x228,                /* Rena's U0 dataset; table 2 */
    GAMEBIT_DIM3_ActNo = 0x229,                          /* table 1; size 4; snowmines3 (unused?) */
    GAMEBIT_CC_LevelControlCameraReady = 0x22A,          /* The DLL names this one itself: CC_LEVEL_CONTROL_CAMERA_READY_GAMEBIT in CClevcontro.c */
    GAMEBIT_ITEM_FireSpellStone1_Used = 0x22B,           /* table 2. Backs the collectable item C-menu entry the game labels "Use SpellStone" (its used bit); and the collectable item C-menu entry the game labels "Use SpellStone" (its owned bit) */
    GAMEBIT_LINKB_LINKSnowPrEnable022C = 0x22C,          /* Read out of the retail placement data: linkb/LINK_SnowPr enableGameBit x1; linkb/GroundAnima sunkGameBit x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CC_LevelControlCameraStop = 0x22D,           /* The DLL names this one itself: CC_LEVEL_CONTROL_CAMERA_STOP_GAMEBIT in CClevcontro.c */
    GAMEBIT_CC_LevelControlCameraGate = 0x22E,           /* The DLL names this one itself: CC_LEVEL_CONTROL_CAMERA_GATE_GAMEBIT in CClevcontro.c */
    GAMEBIT_DIM2_HitAnimTarget022F = 0x22F,              /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines2/HitAnimator objId= param=target; table 2 */
    GAMEBIT_DIM2_ExplodeActivate0230 = 0x230,            /* Read out of the retail placement data: snowmines2/DIM2Explode activateGameBit x12; snowmines2/ExplodeAnim resultGameBit x1; 13 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM2_HitAnimTarget0233 = 0x233,              /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines2/HitAnimator objId= param=target; table 2 */
    GAMEBIT_WC_PlacedSunMoonStones = 0x235,              /* table 2; hint 411 */
    GAMEBIT_CC_Open0236 = 0x236,                         /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/CCwaterShut objId= param=open; capeclaw/CCwaterShut objId= param=open; capeclaw/HitAnimator objId= param=target; table 2 */
    GAMEBIT_CC_SeqUsed0237 = 0x237,                      /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/CCseqobj objId= param=usedBit; table 2 */
    GAMEBIT_IM_TrickyRelated0238 = 0x238,                /* The clearIfClear of IMIceMounta's second Tricky-state music latch, whose clearIfSet is GAMEBIT_IM_TrickyRelated02C1 and whose condition is GAMEBIT_IM_TrickyRelated01ED */
    GAMEBIT_SH_MagicCaveVisible = 0x23A,                 /* table 1; ref hollow/MagicCaveTo Visible */
    GAMEBIT_SH_QueenPortalSpellCast023B = 0x23B,         /* Raised when the player casts the portal spell close enough to the Queen EarthWalker; its neighbour GAMEBIT_SH_Related023C is what then selects her portal-ready event table */
    GAMEBIT_SH_Related023C = 0x23C,                      /* table 2 */
    GAMEBIT_SH_ThornTailRelated023D = 0x23D,             /* table 1; related to ThornTail */
    GAMEBIT_ITEM_SilverKey241_Got = 0x241,               /* table 0. Backs the collectable item C-menu entry the game labels "Use Silver Key" (its owned bit) */
    GAMEBIT_ITEM_SilverKey241_Used = 0x242,              /* table 2. Backs the collectable item C-menu entry the game labels "Use Silver Key" (its used bit) */
    GAMEBIT_ITEM_WCMoonStone_Used = 0x243,               /* table 2. the sun temple DLL checks it as its Walled City inventory bit D. Backs the collectable item C-menu entry the game labels "Use Moon Stone" (its used bit) */
    GAMEBIT_WC_SeqBit180244 = 0x244,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit18; table 2 */
    GAMEBIT_ITEM_TrickyFlame_Got = 0x245,                /* table 2 */
    GAMEBIT_WM_LaserTarToggle024C = 0x24C,               /* Read out of the retail placement data: warlock/WM_LaserTar toggleGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_WM_DoorToKrazTest1Opened = 0x24E,            /* table 2; ref warlock/HitAnimator target */
    GAMEBIT_CF_SeqBit1A024F = 0x24F,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFGoldenPer objId= param=bit1A; table 1 */
    GAMEBIT_CF_SeqBit1A0250 = 0x250,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFGoldenPer objId= param=bit1A; table 1 */
    GAMEBIT_CF_SeqBit1A0251 = 0x251,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFGoldenPer objId= param=bit1A; table 1 */
    GAMEBIT_CF_SeqBit1A0252 = 0x252,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFGoldenPer objId= param=bit1A; table 1 */
    GAMEBIT_DIM2_Open0254 = 0x254,                       /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines2/DIM2IcePlat objId= param=open; table 2 */
    GAMEBIT_DIM2_Open0255 = 0x255,                       /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines2/DIM2IcePlat objId= param=open; table 2 */
    GAMEBIT_LINKB_TrickyStateB = 0x256,                  /* LINKB_levco's second Tricky state bit, paired with GAMEBIT_LINKB_TrickyStateA */
    GAMEBIT_CF_PrisonDooClosedLatch0258 = 0x258,         /* Read out of the retail placement data: clouddungeon/CFPrisonDoo closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CF_PrisonDooClosedLatch0259 = 0x259,         /* Read out of the retail placement data: clouddungeon/CFPrisonDoo closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_ITEM_WCGoldTooth_Used = 0x25A,               /* table 2. the sun temple DLL checks it as its Walled City inventory bit A. Backs the collectable item C-menu entry the game labels "Use Gold Tooth" (its used bit) */
    GAMEBIT_ITEM_WCSilverTooth_Used = 0x25B,             /* table 2. the sun temple DLL checks it as its Walled City inventory bit B. Backs the collectable item C-menu entry the game labels "Use Silver Tooth" (its used bit) */
    GAMEBIT_WC_SeqBit18025C = 0x25C,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit18; table 2 */
    GAMEBIT_WC_SeqBit18025D = 0x25D,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit18; table 2 */
    GAMEBIT_DIM2_IcicleActive = 0x25E,                   /* The DLL names this one itself: GAMEBIT_DIM2_ICICLE_ACTIVE in DIM_Boss.c */
    GAMEBIT_WC_TrexLever4Activated = 0x25F,              /* One of the four wallcity staff levers the T-rex challenge runs on - wclevelcont raises all four at init and again when a run times out, and clears all four as a run starts; Rena has it as wallcity HitAnimator 0x47FF0's target and StaffLeverO 0x4CB3F's activated param */
    GAMEBIT_ITEM_WCMoonStone_Got = 0x264,                /* table 2. Backs the collectable item C-menu entry the game labels "Use Moon Stone" (its owned bit) */
    GAMEBIT_WC_FloorTileRelated0265 = 0x265,             /* Read by WCFloorTile as the last branch of its fall logic, purely to raise its own flag 4 */
    GAMEBIT_DIM2_IciclePhase2Win = 0x266,                /* The DLL names this one itself: GAMEBIT_DIM2_ICICLE_PHASE2_WIN in DIM_Boss.c */
    GAMEBIT_DIM_BossTonsilRouteLow = 0x268,              /* The DLL names this one itself: DIMBOSSTONSIL_GAMEBIT_ROUTE_LOW in DIM_BossTon.c */
    GAMEBIT_DIM_BossFootstepShake = 0x26B,               /* Raised on every DarkIce Mines boss footstep, in the same breath as the dampened camera shake and the rumble - the boss counterpart to GAMEBIT_DR_KTrexFootfallShake. MAGICMaker reads the same bit as its spawn bit, so the boss's footfalls are what spawn its magic */
    GAMEBIT_DIM2_Open026C = 0x26C,                       /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines2/DIM2IcePlat objId= param=open; table 2 */
    GAMEBIT_DIM2_FXEmitDisable026D = 0x26D,              /* Read out of the retail placement data: snowmines2/FXEmit disableGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM2_IcePlatClosedLatch026E = 0x26E,         /* Read out of the retail placement data: snowmines2/DIM2IcePlat closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM2_IcePlatClosedLatch026F = 0x26F,         /* Read out of the retail placement data: snowmines2/DIM2IcePlat closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM2_IcePlatClosedLatch0270 = 0x270,         /* Read out of the retail placement data: snowmines2/DIM2IcePlat closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_PushableRelated0272 = 0x272,                 /* table 2; ref snowmines2/HitAnimator target */
    GAMEBIT_WC_TrexAnimTarget0274 = 0x274,               /* Wallcity HitAnimator 0x4CB89's target - wclevelcont raises it both as a T-rex run starts and when one is beaten, and drops it when a run times out */
    GAMEBIT_ITEM_Spirit1_Used = 0x277,                   /* table 1 */
    GAMEBIT_DIM2_SeqBit1A0278 = 0x278,                   /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines2/DIM2SeqObje objId= param=bit1A; snowmines2/StaffLeverO objId= param=activated; table 2 */
    GAMEBIT_DIM2_SeqBit180279 = 0x279,                   /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines2/DIM2SeqObje objId= param=bit18; snowmines2/DIM2IceGrat objId= param=open; table 2 */
    GAMEBIT_DIM2_IceGratClosedLatch027A = 0x27A,         /* Read out of the retail placement data: snowmines2/DIM2IceGrat closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_ITEM_SilverKey282_Got = 0x282,               /* table 2. Backs the collectable item C-menu entry the game labels "Use Silver Key" (its owned bit) */
    GAMEBIT_ITEM_SilverKey282_Used = 0x283,              /* table 2. Backs the collectable item C-menu entry the game labels "Use Silver Key" (its used bit) */
    GAMEBIT_DIM2_SnowballLaunch = 0x288,                 /* The DLL names this one itself: DIM2_SNOWBALL_LAUNCH_GAME_BIT in DIM2SnowBal.c */
    GAMEBIT_NW_SeqUsed0289 = 0x289,                      /* Named from map data alone - nothing in the code or in any name list mentions it: wastes/NW_seqobjec objId= param=usedBit; table 2 */
    GAMEBIT_SH_SeqNeed0299 = 0x299,                      /* Named from map data alone - nothing in the code or in any name list mentions it: hollow/SH_newseqob objId= param=needBit; hollow/TrigBits objId= param=activate; table 2 */
    GAMEBIT_ITEM_Spirit2_Used = 0x29A,                   /* table 2; hint 316 */
    GAMEBIT_WM_SpiritPlace2Ready = 0x29B,                /* table 2; gates spirit-place 2 and its return pad */
    GAMEBIT_WC_TrexChallengeComplete = 0x2A5,            /* The Walled City T-rex challenge has been beaten - polled through the timed run to end it with a checkpoint save, and the bit wclevelcont_init reads back into WCLEVELCTL_FLAG_TREX */
    GAMEBIT_WC_TrexLever2Activated = 0x2A6,              /* One of the four wallcity staff levers the T-rex challenge runs on - wclevelcont raises all four at init and again when a run times out, and clears all four as a run starts; Rena has it as wallcity HitAnimator 0x47FEE's target and StaffLeverO 0x4CB3E's activated param, the same lever GAMEBIT_WC_TrexLever2Enabled switches on */
    GAMEBIT_WC_HitAnimTarget02B0 = 0x2B0,                /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/HitAnimator objId= param=target; table 2 */
    GAMEBIT_WC_TrexRunRequested = 0x2B1,                 /* A T-rex run has been asked for: while it is up and the challenge is unbeaten, wclevelcont arms the run, and a timeout clears it */
    GAMEBIT_SH_OpenedGateToCape = 0x2B2,                 /* table 2; ref hollow/StaffLeverO activated */
    GAMEBIT_TimeListPromptAccepted = 0x2B3,              /* The best-times prompt was answered with its first option; GAMEBIT_TimeListPromptDeclined covers every other answer */
    GAMEBIT_SH_SeqUsed02B4 = 0x2B4,                      /* Named from map data alone - nothing in the code or in any name list mentions it: hollow/SH_newseqob objId= param=usedBit; hollow/MagicCaveTo objId= param=Visible; table 2 */
    GAMEBIT_LV_CapturedByLightFoot = 0x2B5,              /* table 2; hint 346 */
    GAMEBIT_LV_TestStrengthBestTime1 = 0x2B6,            /* table 2; size 16 */
    GAMEBIT_LV_TestTrackingBestTime1 = 0x2B7,            /* table 2; size 16 */
    GAMEBIT_SC_StaffLeversEnabled = 0x2B8,               /* Rena has it driving the enabled param of all four swapcircle StaffLeverO objects; sc_levelcontrol raises it as a timed totem run begins and drops it at init and on both ways out of the run */
    GAMEBIT_ENV_dayNo = 0x2BA,                           /* table 3; size 8; Counts from 0 to 27, increasing every morning in-game time. Used for environmental effects. */
    GAMEBIT_SC_TotemBondComplete = 0x2BC,                /* The DLL names this one itself: SC_TOTEM_BOND_GAMEBIT_COMPLETE in SC_totembon.c */
    GAMEBIT_WM_NpcRenderGate02BD = 0x2BD,                /* In DLL 0x200's gated map act the NPC draws nothing at all unless this is set */
    GAMEBIT_SH_FirstMagicCaveDoorOpen = 0x2C0,           /* table 2; ref hollow/HitAnimator target */
    GAMEBIT_IM_TrickyRelated02C1 = 0x2C1,                /* table 0; set when starting tricky landing scene */
    GAMEBIT_DIM2_SeqBit1A02C2 = 0x2C2,                   /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines2/DIM2SeqObje objId= param=bit1A; table 2 */
    GAMEBIT_DIM_ReachedBottom = 0x2C3,                   /* table 2; hint 291 */
    GAMEBIT_SH_SeqUsed02C5 = 0x2C5,                      /* Named from map data alone - nothing in the code or in any name list mentions it: hollow/SH_newseqob objId= param=usedBit; table 1 */
    GAMEBIT_SC_LVBlock3Related02C6 = 0x2C6,              /* One of the three bits sc_levelcontrol raises the moment GAMEBIT_ITEM_LVBlock3_Used is set; Rena has this one as the target of swapcircle's HitAnimator 0x49329 */
    GAMEBIT_SC_SeqBit1A02C8 = 0x2C8,                     /* Named from map data alone - nothing in the code or in any name list mentions it: swapcircle/SC_sequence objId= param=bit1A; table 0 */
    GAMEBIT_SC_SeqBit1802C9 = 0x2C9,                     /* Named from map data alone - nothing in the code or in any name list mentions it: swapcircle/SC_sequence objId= param=bit18; table 2 */
    GAMEBIT_SC_SeqBit1802CA = 0x2CA,                     /* Named from map data alone - nothing in the code or in any name list mentions it: swapcircle/SC_sequence objId= param=bit18; table 2 */
    GAMEBIT_LV_TestTrackingBestTime2 = 0x2CB,            /* table 2; size 16 */
    GAMEBIT_LV_TestTrackingBestTime3 = 0x2CC,            /* table 2; size 16 */
    GAMEBIT_SC_SteppingClosedLatch02CD = 0x2CD,          /* Read out of the retail placement data: swapcircle/SC_stepping closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SC_LVBlock3Related02CE = 0x2CE,              /* One of the three bits sc_levelcontrol raises the moment GAMEBIT_ITEM_LVBlock3_Used is set */
    GAMEBIT_LV_EscapedFromPole = 0x2D0,                  /* table 2; hint 347 */
    GAMEBIT_WC_TempleDiaAStage1 = 0x2D1,                 /* Walled City temple rotating-dial (bank A) - stage 1 complete, gWcTempleDiaGameBitsA[1]; ORed into WCTempleDiaState.stageMask, which picks the dial speed from gWcTempleDiaTargetSpeedTableA and drives part visibility */
    GAMEBIT_WC_TempleDiaAStage2 = 0x2D2,                 /* Walled City temple rotating-dial (bank A) - stage 2 complete, gWcTempleDiaGameBitsA[2]; ORed into WCTempleDiaState.stageMask, which picks the dial speed from gWcTempleDiaTargetSpeedTableA and drives part visibility */
    GAMEBIT_WC_HitAnimTarget02D4 = 0x2D4,                /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/HitAnimator objId= param=target; wallcity/HitAnimator objId= param=target; table 2 */
    GAMEBIT_WC_HitAnimTarget02D5 = 0x2D5,                /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/HitAnimator objId= param=target; wallcity/HitAnimator objId= param=target; table 2 */
    GAMEBIT_ITEM_FireGem_Got = 0x2D6,                    /* table 1. Backs the collectable item C-menu entry the game labels "Place Fire Gem" (its owned bit) */
    GAMEBIT_LV_TestStrengthBestTime2 = 0x2D7,            /* table 2; size 16 */
    GAMEBIT_LV_TestStrengthBestTime3 = 0x2D8,            /* table 2; size 16 */
    GAMEBIT_SC_SeqBit1A02D9 = 0x2D9,                     /* Named from map data alone - nothing in the code or in any name list mentions it: swapcircle/SC_sequence objId= param=bit1A; table 0 */
    GAMEBIT_SC_Open02DC = 0x2DC,                         /* Named from map data alone - nothing in the code or in any name list mentions it: swapcircle/SC_Shrine_d objId= param=open; table 2 */
    GAMEBIT_BlastedDamageBase = 0x2DE,                   /* The DLL names this one itself: BLASTED_GAMEBIT_DAMAGE_BASE in 345.c */
    GAMEBIT_CF_HitAnimTarget02E1 = 0x2E1,                /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/HitAnimator objId= param=target; fortress/CFExplodeFl objId= param=exploded; fortress/CFseqobject objId= param=bit1A; table 2 */
    GAMEBIT_SC_ShrinedClosedLatch02E6 = 0x2E6,           /* Read out of the retail placement data: swapcircle/SC_Shrine_d closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_LV_ChiefStartedTest = 0x2E7,                 /* table 2; hint 348 */
    GAMEBIT_ITEM_WaterSpellStone1_Got = 0x2E8,           /* table 2; hint 336; ref dfptop/VFP_PodiumP key. CAUTION: CRCloudRace names the same bit its abort trigger, which is not obviously the same thing as holding the stone. Backs the collectable item C-menu entry the game labels "Use SpellStone" (its owned bit) */
    GAMEBIT_WC_SeqBit1802EB = 0x2EB,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit18; table 2 */
    GAMEBIT_WC_TempleDiaBStage1 = 0x2EC,                 /* Walled City temple rotating-dial (bank B) - stage 1 complete, gWcTempleDiaGameBitsB[1]; bank chosen by ObjAnim.bankIndex != 0, otherwise as bank A */
    GAMEBIT_WC_TempleDiaBStage2 = 0x2EF,                 /* Walled City temple rotating-dial (bank B) - stage 2 complete, gWcTempleDiaGameBitsB[2]; bank chosen by ObjAnim.bankIndex != 0, otherwise as bank A */
    GAMEBIT_WC_FinalStopwatchTarget = 0x2F0,             /* Wallcity CNTstopwatc 0x49129's target, raised as the Walled City final puzzle completes */
    GAMEBIT_WC_HitAnimTarget02F1 = 0x2F1,                /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/HitAnimator objId= param=target; table 1 */
    GAMEBIT_WC_TempleDiaAStage0 = 0x2F8,                 /* Walled City temple rotating-dial (bank A) - stage 0 complete, gWcTempleDiaGameBitsA[0]; ORed into WCTempleDiaState.stageMask, which picks the dial speed from gWcTempleDiaTargetSpeedTableA and drives part visibility */
    GAMEBIT_WM_NpcIdleSuppressed02FB = 0x2FB,            /* table 0; while clear, DLL 0x200's NPC runs its idle animation - raising it stops the idle outright. Spelled 763 in retail */
    GAMEBIT_CFRelated02FC = 0x2FC,                       /* table 1 */
    GAMEBIT_CFRelated02FD = 0x2FD,                       /* table 1 */
    GAMEBIT_CFRelated02FE = 0x2FE,                       /* table 1 */
    GAMEBIT_CFRelated02FF = 0x2FF,                       /* table 1 */
    GAMEBIT_OFB_DFPObjCreaGameBitA0300 = 0x300,          /* Read out of the retail placement data: kraztest/DFP_ObjCrea gameBitA x2 */
    GAMEBIT_CF_Open0302 = 0x302,                         /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/SC_Shrine_d objId= param=open; fortress/SC_Shrine_d objId= param=open; table 1 */
    GAMEBIT_CF_Open0303 = 0x303,                         /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/SC_Shrine_d objId= param=open; table 2 */
    GAMEBIT_WC_SeqBit1A0304 = 0x304,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit1A; table 2 */
    GAMEBIT_CF_SCShrinedClosedLatch0305 = 0x305,         /* Read out of the retail placement data: fortress/SC_Shrine_d closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_KytesMumQuestB = 0x30A,                      /* Kyte's Mum second quest stage gate, gKytesMumQuestBits[1] (trigger id 2); the first stage is gated on GAMEBIT_CF_SavedQueen = 0x43 */
    GAMEBIT_CF_WindLiftActivation030D = 0x30D,           /* Read out of the retail placement data: fortress/CFWindLift activationGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_WM_NpcItemUsed0310 = 0x310,                  /* Raised the instant the player uses one of DLL 0x200's accepted items on that NPC - only reachable once GAMEBIT_WM_FoundKrystal is set - together with GAMEBIT_WM_NpcItemUsed04D1 and a bump to the NPC's interaction count */
    GAMEBIT_DIM_BossTonsilRouteHigh = 0x311,             /* The DLL names this one itself: DIMBOSSTONSIL_GAMEBIT_ROUTE_HIGH in DIM_BossTon.c */
    GAMEBIT_DIM3_WarpEnable312 = 0x312,                  /* Rena's U0 dataset; table 0 */
    GAMEBIT_DIM3_WarpEnable313 = 0x313,                  /* Rena's U0 dataset; table 0 */
    GAMEBIT_WM_NpcSecondItemUsed = 0x314,                /* Raised from the DLL 0x200 NPC's anim event 1 once its interaction count reaches 2, so the second item has landed */
    GAMEBIT_WC_XYZAnimatorTrigger0335 = 0x335,           /* Read out of the retail placement data: wallcity/XYZAnimator triggerGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_ITEM_Key336_Got = 0x336,                     /* table 1; XXX where is this key from?. Backs the collectable item C-menu entry the game labels "Use Key" (its owned bit) */
    GAMEBIT_WC_FloorTilesReset = 0x338,                  /* Puts a Walled City floor tile back: on sight of it the tile snaps to its placement Y and enters its restore phase. Spelled 824 in retail */
    GAMEBIT_CF_SeqBit1A033D = 0x33D,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFseqobject objId= param=bit1A; table 1 */
    GAMEBIT_FinalBoss_ActNo = 0x349,                     /* table 1; size 4 */
    GAMEBIT_WC_TrexRetryBlocked034D = 0x34D,             /* Blocks the retry: when a T-rex run times out, wclevelcont only re-arms the four levers if this is clear */
    GAMEBIT_CF_SeqBit180359 = 0x359,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFseqobject objId= param=bit18; table 2 */
    GAMEBIT_DIM_Bike_HitboxEnabled = 0x35F,              /* Rena's U0 dataset; table 2 */
    GAMEBIT_WC_ObjGroups = 0x36A,                        /* table 3; size 32 */
    GAMEBIT_LINKB_TrickyStateLatch = 0x36E,              /* The GameBitLatch condition LINKB_levco hangs its Tricky-state music on */
    GAMEBIT_WM_CrystalRumbleActive = 0x370,              /* table 0; raised while the rising crystal is randomly shaking the camera, and dropped the moment the finale quake proper takes over */
    GAMEBIT_WC_SeqBit180371 = 0x371,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit18; table 2 */
    GAMEBIT_KrazTest1Related0372 = 0x372,                /* table 3; set when entering Krazoa test 1, cave beside WarpStone */
    GAMEBIT_DIM2_ObjGroups = 0x373,                      /* table 3; size 32 */
    GAMEBIT_IM_BikeRelated0374 = 0x374,                  /* Cleared by IMIceMounta's bike teardown, in the run of bits that also drops GAMEBIT_IM_OnBike and closes objgroup 2 */
    GAMEBIT_IM_SeqBit1A0375 = 0x375,                     /* Named from map data alone - nothing in the code or in any name list mentions it: newicemount/IMSeqObject objId= param=bit1A; newicemount3/IMSeqObject objId= param=bit1A; table 2 */
    GAMEBIT_IM_SeqBit180376 = 0x376,                     /* Named from map data alone - nothing in the code or in any name list mentions it: newicemount/IMSeqObject objId= param=bit18; newicemount3/IMSeqObject objId= param=bit18; table 2 */
    GAMEBIT_IM_DoorOpen = 0x377,                         /* table 2; ref newicemount/HitAnimator target */
    GAMEBIT_IM_BikeRelated0378 = 0x378,                  /* table 1; set when approaching SharpClaws in hut, cleared after race */
    GAMEBIT_IM_BikeRelated0379 = 0x379,                  /* table 2; set to 0x19 when finishing race even though max is 1 - in kiosk, related to demo mode - map 0x19 is newicemount3 */
    GAMEBIT_IM_FinishedRace = 0x37A,                     /* table 2; hint 262 */
    GAMEBIT_IMRelated037B = 0x37B,                       /* table 2 */
    GAMEBIT_IM_BikeRelated037C = 0x37C,                  /* Cleared by IMIceMounta's bike teardown, in the run of bits that also drops GAMEBIT_IM_OnBike and closes objgroup 2 */
    GAMEBIT_IM_SeqBit1A037D = 0x37D,                     /* Named from map data alone - nothing in the code or in any name list mentions it: newicemount/IMSeqObject objId= param=bit1A; newicemount3/IMSeqObject objId= param=bit1A; table 2 */
    GAMEBIT_IM_SeqBit18037E = 0x37E,                     /* Named from map data alone - nothing in the code or in any name list mentions it: newicemount/IMSeqObject objId= param=bit18; newicemount3/IMSeqObject objId= param=bit18; table 2 */
    GAMEBIT_LINKB_SeqUsed037F = 0x37F,                   /* Named from map data alone - nothing in the code or in any name list mentions it: linkb/LINKB_seqob objId= param=usedBit; table 2 */
    GAMEBIT_LINKB_AlternatePath = 0x380,                 /* Seen at LINKB_levco's stage 3, it routes the sequence down its alternate path instead of advancing immediately */
    GAMEBIT_LINKB_SeqUsed0381 = 0x381,                   /* Named from map data alone - nothing in the code or in any name list mentions it: linkb/LINKB_seqob objId= param=usedBit; table 2 */
    GAMEBIT_IM_HutRelated0382 = 0x382,                   /* table 2; changed when near hut */
    GAMEBIT_LINKB_HitAnimTarget0383 = 0x383,             /* Named from map data alone - nothing in the code or in any name list mentions it: linkb/HitAnimator objId= param=target; table 2 */
    GAMEBIT_LINKB_Stage1Reached = 0x384,                 /* One of the five stages LINKB_levco's Tricky sequence resumes from - on load it walks them from 5 down to 1 and restarts at the highest one reached; stage 1, the one tricky.c pairs with stage 2 to find its window - in map cell 0x38 Tricky offers to find food only while stage 1 is reached and stage 2 is not */
    GAMEBIT_LINKB_Stage2Reached = 0x385,                 /* One of the five stages LINKB_levco's Tricky sequence resumes from - on load it walks them from 5 down to 1 and restarts at the highest one reached; stage 2, raised once the player has Tricky food in hand, and the bit whose absence keeps tricky.c's find-food offer open */
    GAMEBIT_LINKB_Stage3Reached = 0x386,                 /* One of the five stages LINKB_levco's Tricky sequence resumes from - on load it walks them from 5 down to 1 and restarts at the highest one reached; raised once Tricky has taken enough hits */
    GAMEBIT_LINKB_Stage4Reached = 0x387,                 /* One of the five stages LINKB_levco's Tricky sequence resumes from - on load it walks them from 5 down to 1 and restarts at the highest one reached; raised off GAMEBIT_LINKB_TrickyStateA or the alternate path */
    GAMEBIT_MMP_LevelControlMusicLatchA = 0x389,         /* The DLL names this one itself: MMP_LEVEL_CONTROL_GAMEBIT_MUSIC_LATCH_A in MMP_levelco.c */
    GAMEBIT_MMP_SeqBit1A038A = 0x38A,                    /* Named from map data alone - nothing in the code or in any name list mentions it: moonpass/MMP_seqobje objId= param=bit1A; moonpass/MMP_seqobje objId= param=bit18; table 2 */
    GAMEBIT_WC_HitAnimTarget038C = 0x38C,                /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/HitAnimator objId= param=target; table 2 */
    GAMEBIT_WM_FinaleQuakeActive = 0x38D,                /* Krazoa Palace finale: set by WM_Crystal (dll_020E) once fully risen after the 6th spirit is returned, gating the WM_sun bank-0 quake/envfx countdown until it clears and 0x38F fires */
    GAMEBIT_WM_FinaleQuakeDone = 0x38F,                  /* The Warlock Mountain finale quake has run its course - WM_sun raises it as the quake timer expires and clears GAMEBIT_WM_FinaleQuakeActive, and WM_Crystal frees itself on sight of it */
    GAMEBIT_KrazTest1Related0390 = 0x390,                /* table 3; set when entering Krazoa test 1, cleared when talking to WarpStone */
    GAMEBIT_WC_SeqBit1A0392 = 0x392,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit1A; table 2 */
    GAMEBIT_WarpActive0393 = 0x393,                      /* A warp is in progress - NW_levcontr and SH_LevelCon both make it the GameBitLatch condition their level controllers attach to MUSICTRIG_Teleport (0x36, track 85 SNGTeleport) */
    GAMEBIT_DBAY_ObjGroups = 0x397,                      /* table 3; size 32 */
    GAMEBIT_NW_GeyserComplete = 0x398,                   /* SnowHorn Wastes geyser completion; set by NW_geyser after its disable bit hides it, consumed by NW_levcontr to re-enable the geyser object group */
    GAMEBIT_IM_WaterRelated03A0 = 0x3A0,                 /* table 3; set when getting out of water */
    GAMEBIT_IM_Done = 0x3A1,                             /* table 3; Tricky now follows you */
    GAMEBIT_IM_BikeRelated03A2 = 0x3A2,                  /* table 1; set when gaining control of bike, cleared at end */
    GAMEBIT_IM_BikeRelated03A3 = 0x3A3,                  /* table 1; cleared at end of race */
    GAMEBIT_SH_Related03AA = 0x3AA,                      /* table 2 */
    GAMEBIT_ENV_disableDayFX1 = 0x3AB,                   /* table 3 */
    GAMEBIT_ENV_disableDayFX2 = 0x3AC,                   /* table 3; disable an environment effect */
    GAMEBIT_IM_ObjGroups = 0x3AD,                        /* table 3; size 32 */
    GAMEBIT_IM_EnteredHut = 0x3AE,                       /* table 2 */
    GAMEBIT_ENV_disableDayFX3 = 0x3AF,                   /* table 3; disable an environment effect */
    GAMEBIT_ENV_isOutdoor = 0x3B0,                       /* table 3; disable rain, snow */
    GAMEBIT_CC_ObjGroups = 0x3B7,                        /* table 3; size 32 */
    GAMEBIT_IM_BikeRelated03B9 = 0x3B9,                  /* table 1; set when approaching SharpClaws in hut, cleared after race */
    GAMEBIT_IM_BikeRelated03BA = 0x3BA,                  /* table 2; set at some point during race */
    GAMEBIT_DBEggCarried = 0x3C4,                        /* An egg is already in hand - DB_egg raises it at both points an egg is taken, and refuses a fresh pickup while it is up, so it works as the carry lock */
    GAMEBIT_DIM_CapturedCannon = 0x3CF,                  /* table 2; hint 286 */
    GAMEBIT_DIM_CannonHold03D0 = 0x3D0,                  /* Read out of the retail placement data: snowmines/DIMCannon holdGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MoonSeedSpot9Harvested = 0x3D2,              /* One of the eleven moon-seed planting spots MSPlantingS maps from its placement ident: spot 9, ident 0x476AE, whose map Rena does not record. This is its harvested bit, raised once the grown plant is cut and taken */
    GAMEBIT_MoonSeedSpot9Planted = 0x3D5,                /* One of the eleven moon-seed planting spots MSPlantingS maps from its placement ident: spot 9, ident 0x476AE, whose map Rena does not record. This is its planted bit; planting also decrements the shared GAMEBIT_ITEM_MoonSeed_Count */
    GAMEBIT_CC_LevelControlGroup1FDisabled = 0x3D6,      /* The DLL names this one itself: CC_LEVEL_CONTROL_GROUP_1F_DISABLED_GAMEBIT in CClevcontro.c */
    GAMEBIT_CC_LevelControlGroup1DEnabled = 0x3D7,       /* The DLL names this one itself: CC_LEVEL_CONTROL_GROUP_1D_ENABLED_GAMEBIT in CClevcontro.c */
    GAMEBIT_ITEM_DinoHorn_3D8 = 0x3D8,                   /* table 0 */
    GAMEBIT_CC_XYZAnimatorCompletion03DD = 0x3DD,        /* Read out of the retail placement data: capeclaw/XYZAnimator completionGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SB_ObjGroups = 0x3E0,                        /* table 3; size 32; frontend, galleonship, Ship Battle */
    GAMEBIT_DIM_TriggerLostInBlizzard = 0x3E2,           /* table 0; Trigger scene where Fox walks off into blizzard and comes back */
    GAMEBIT_NW_SnowHorn03E3 = 0x3E3,                     /* table 0; related to riding SnowHorn */
    GAMEBIT_DIM_PushBlocBit03E5 = 0x3E5,                 /* A DarkIce push-block's gamebit, from its placement's field at 0x18. That slot is corroborated rather than assumed: the Walled City push blocks are the same DLL and read the same offset, and the three ids they hold there are exactly GAMEBIT_WC_Switch1/2/3Activated, which were named from WCLevelCont's code. PushableObjectDef overruns the 0x24 record at its tail, but this field is inside it */
    GAMEBIT_DIM_LostInBlizzard = 0x3E8,                  /* table 0; Triggered by 0x3E2, actually starts the scene */
    GAMEBIT_ITEM_NWFood_Got = 0x3E9,                     /* table 0; Alpine Root while riding SnowHorn through blizzard; collecting one sets this to 1, then 0 */
    GAMEBIT_SH_Open03EB = 0x3EB,                         /* Named from map data alone - nothing in the code or in any name list mentions it: hollow/SH_Portcull objId= param=open; hollow/StaffLeverO objId= param=activated; table 2 */
    GAMEBIT_CC_GasVentControlIntroTrigger = 0x3EC,       /* The DLL names this one itself: CC_GAS_VENT_CONTROL_INTRO_TRIGGER_GAMEBIT in CCgasventCo.c */
    GAMEBIT_TrickyColorChangeSeen = 0x3ED,               /* The DLL names this one itself: TRICKY_COLOR_CHANGE_SEEN_GAMEBIT in tricky.c */
    GAMEBIT_DBAY_ActNo = 0x3EE,                          /* table 1; size 4 */
    GAMEBIT_DIM_SeqBit1803EF = 0x3EF,                    /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/DIMSeqObjec objId= param=bit18; snowmines/DIMSeqObjec objId= param=bit18; table 2 */
    GAMEBIT_ITEM_CCGoldBar_Used = 0x3F0,                 /* table 2; size 3 */
    GAMEBIT_ITEM_DinoHorn_3F1 = 0x3F1,                   /* table 0 */
    GAMEBIT_ITEM_HighTopGold_Found = 0x3F4,              /* table 2; hint 319 */
    GAMEBIT_ITEM_FuelCell_Count = 0x3F5,                 /* table 2; size 8. Backs the collectable item C-menu entry the game labels "Use Fuel Cells" (its owned bit) */
    GAMEBIT_ITEM_TrickyBall_Usable = 0x3F8,              /* table 2; set after throwing and you can throw multiple balls! */
    GAMEBIT_WorldMapCloudFort = 0x3FA,                   /* table 2; hint 323; unlocked CloudRunner Fortress on world map */
    GAMEBIT_WorldMapWallCity = 0x3FB,                    /* table 2; hint 359; unlocked Walled City on world map */
    GAMEBIT_WorldMapDragRock = 0x3FC,                    /* table 2; hint 384; unlocked Dragon Rock on world map */
    GAMEBIT_TTH_FuelCell_3FD = 0x3FD,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_WM_ObjGroups = 0x405,                        /* table 3; size 32 */
    GAMEBIT_DIM2_LeverActivated0409 = 0x409,             /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines2/StaffLeverO objId= param=activated; snowmines2/DIM2SeqObje objId= param=bit1A; snowmines2/DIM2TrapDoo objId= param=open; table 0 */
    GAMEBIT_DIM_HitAnimTarget040A = 0x40A,               /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/HitAnimator objId= param=target; table 2 */
    GAMEBIT_TTH_FuelCell_40B = 0x40B,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_MMP_SeqBit1A040F = 0x40F,                    /* Named from map data alone - nothing in the code or in any name list mentions it: moonpass/MMP_seqobje objId= param=bit1A; table 2 */
    GAMEBIT_MMP_SeqBit1A0410 = 0x410,                    /* Named from map data alone - nothing in the code or in any name list mentions it: moonpass/MMP_seqobje objId= param=bit1A; table 2 */
    GAMEBIT_SH_FuelCell_QueenCave = 0x416,               /* table 2; ref hollow/fuelCell Collected */
    GAMEBIT_TTH_FuelCell_417 = 0x417,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_SH_FuelCell_BesideWarpStone1 = 0x418,        /* table 2; ref hollow/fuelCell Collected */
    GAMEBIT_TTH_FuelCell_419 = 0x419,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_SH_FuelCell_BesideWarpStone2 = 0x41A,        /* table 2; ref hollow/fuelCell Collected */
    GAMEBIT_TTH_FuelCell_41B = 0x41B,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_MMP_SeqBit18041C = 0x41C,                    /* Named from map data alone - nothing in the code or in any name list mentions it: moonpass/MMP_seqobje objId= param=bit18; moonpass/MMP_seqobje objId= param=bit18; table 2 */
    GAMEBIT_TTH_FuelCell_41E = 0x41E,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_InsideGal_ObjGroups = 0x421,                 /* table 3; size 32 */
    GAMEBIT_DBEggSinkEnabled = 0x426,                    /* While set, a drifting egg becomes grabbable and its water offset falls; once past -7 the egg counts itself into GAMEBIT_DBEggsSunkCount and goes to its sinking mode */
    GAMEBIT_DBEggsSunkCount = 0x428,                     /* How many eggs have sunk - a counter, incremented by read-add-write rather than set as a flag */
    GAMEBIT_WM_GalleonRelated429 = 0x429,                /* table 2; related to savegame/obj groups/galleon */
    GAMEBIT_DBEggRespawn = 0x42A,                        /* Waiting to respawn, an egg rebuilds itself from its placement def the moment this is set; while it is clear the egg just puffs particles */
    GAMEBIT_DIM_XYZAnimatorTrigger042B = 0x42B,          /* Read out of the retail placement data: snowmines/XYZAnimator triggerGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM_XYZAnimatorCompletion042C = 0x42C,       /* Read out of the retail placement data: snowmines/XYZAnimator completionGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_ObjGroups = 0x42E,                       /* table 3; size 32 */
    GAMEBIT_DIM2_LeverActivated0430 = 0x430,             /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines2/StaffLeverO objId= param=activated; snowmines2/DIM2TrapDoo objId= param=open; snowmines2/DIM2SeqObje objId= param=bit1A; table 0 */
    GAMEBIT_DIM3_ObjGroups = 0x443,                      /* table 3; size 32 */
    GAMEBIT_TTH_FuelCell_447 = 0x447,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_DIM2_HitAnimTarget0449 = 0x449,              /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines2/HitAnimator objId= param=target; snowmines2/HitAnimator objId= param=target; snowmines2/HitAnimator objId= param=target (+2 more); table 2 */
    GAMEBIT_DBEggCurveStart = 0x44D,                     /* An egg held for its curve ride waits on this bit and nothing else before entering its curve mode */
    GAMEBIT_MenuRelated044F = 0x44F,                     /* table 0; set by n_rareware DLL */
    GAMEBIT_SH_ObjGroups = 0x452,                        /* table 3; size 32; also LinkG 0x00: bloops 0x06: switch to open Queen cave? */
    GAMEBIT_ITEM_MMPKey_Used = 0x453,                    /* table 2; hint 299; ref moonpass/HitAnimator target. Backs the collectable item C-menu entry the game labels "Use Key" (its used bit) */
    GAMEBIT_TTH_FuelCell_456 = 0x456,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_TTH_FuelCell_457 = 0x457,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_ObjGroups = 0x458,                        /* table 3; size 32. CAUTION: this is an ObjGroups mask, several bits wide, yet CRCloudRace reads it as a single boolean it calls drag-rock-cleared - one of the two readings is wrong */
    GAMEBIT_CT_ObjGroups = 0x45A,                        /* table 3; size 32 */
    GAMEBIT_NW_FuelCell_45D = 0x45D,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_NW_FuelCell_45E = 0x45E,                     /* accidentally assigned to two fuel cells; Rena's U0 dataset; table 2 */
    GAMEBIT_NW_FuelCell_45F = 0x45F,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_SHBOT_SHwhitemusBit0460 = 0x460,             /* Read out of the retail placement data: hollow2/SH_whitemus gameBitId x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SHBOT_SHwhitemusBit0461 = 0x461,             /* Read out of the retail placement data: hollow2/SH_whitemus gameBitId x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SHBOT_SHwhitemusBit0462 = 0x462,             /* Read out of the retail placement data: hollow2/SH_whitemus gameBitId x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SHBOT_SHwhitemusBit0463 = 0x463,             /* Read out of the retail placement data: hollow2/SH_whitemus gameBitId x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SHBOT_SHwhitemusBit0464 = 0x464,             /* Read out of the retail placement data: hollow2/SH_whitemus gameBitId x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_IM_FuelCell_465 = 0x465,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_TRICKYCURVE_PLAYER_HIT = 0x468,              /* Hard-coded, area-agnostic "TrickyCurve" hazard-trigger hit-while-sliding signal: set by DFP_ForceAw/DFSH_LaserB/the generic laserbeam when the player enters the trigger box in the sliding anim state (0x1d7) instead of taking a normal hit; polled and cleared by the generic bone-particle-effect module, which arms a particle timer and plays an SFXsc_mumble01 reaction. DFP_ForceAw names the same bit TRICKY_CURVE_GAMEBIT_HIT */
    GAMEBIT_Dll1CEContentsGate = 0x46D,                  /* The DLL names this one itself: DLL1CE_CONTENTS_GATE_GAMEBIT in 462.c */
    GAMEBIT_Dll197StageComplete = 0x472,                 /* The DLL names this one itself: DLL197_STAGE_COMPLETE_GAMEBIT in 407.c */
    GAMEBIT_DBSH_ObjGroups = 0x473,                      /* table 3; size 32 */
    GAMEBIT_Dll197StageResetGate = 0x474,                /* The DLL names this one itself: DLL197_STAGE_RESET_GATE_GAMEBIT in 407.c */
    GAMEBIT_IM_FuelCell_47A = 0x47A,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_GM_ObjGroups = 0x47B,                        /* table 3; size 32 */
    GAMEBIT_CD_ObjGroups = 0x47C,                        /* table 3; size 32 */
    GAMEBIT_DF_ObjGroups = 0x480,                        /* table 3; size 32 */
    GAMEBIT_IM_FuelCell_CheatCave = 0x484,               /* table 2; ref newicemount/fuelCell Collected */
    GAMEBIT_NW_FuelCell_485 = 0x485,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_NW_FuelCell_486 = 0x486,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_NW_FuelCell_487 = 0x487,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_NW_FuelCell_489 = 0x489,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_NW_FuelCell_48A = 0x48A,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_NW_MammothTumbleweedCount = 0x48B,           /* SnowHorn Wastes mammoth's tumbleweed-bush capture count (0-3, persists across reload); reaching 3 completes the air-meter rescue sequence for the SnowHorn Gate Keeper, and Tricky polls it to sync its tumbleweed-chase substate */
    GAMEBIT_SHBOT_FuelCell_48C = 0x48C,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_SHBOT_FuelCell_48D = 0x48D,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_LINKC_FuelCell_48E = 0x48E,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_LINKC_FuelCell_48F = 0x48F,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_MMP_FuelCell_490 = 0x490,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_FuelCell_491 = 0x491,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_DIM_ActNo = 0x492,                           /* table 1; size 4 */
    GAMEBIT_DIM_ObjGroups = 0x493,                       /* table 3; size 32 */
    GAMEBIT_CC_FuelCell_494 = 0x494,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_CC_FuelCell_495 = 0x495,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_CC_FuelCell_496 = 0x496,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_CloudRaceRaceActive = 0x497,                 /* The DLL names this one itself: CRCLOUDRACE_GAMEBIT_RACE_ACTIVE in crcloudrace.h */
    GAMEBIT_CloudRaceInFinishVolume = 0x499,             /* The CloudRunner race's in-finish-volume latch, which CRCloudRace both sets and clears around its abort and finish checks - its own alias spelled it IN_FINISH_VOLUME; DLL 597 also raises it from a vehicle anim event, on every bike but the SharpClaw clawbikes */
    GAMEBIT_SpellStoneRelated049A = 0x49A,               /* table 1 */
    GAMEBIT_CF_DiscoveredGoldMine = 0x49B,               /* table 1; hint 331 */
    GAMEBIT_CF_SeqBit1A049C = 0x49C,                     /* Named from map data alone - nothing in the code or in any name list mentions it: cloudrace/CFRaceSeqob objId= param=bit1A; cloudrace/CFRaceSeqob objId= param=bit18; table 1 */
    GAMEBIT_CloudRaceRaceStarted = 0x49D,                /* The DLL names this one itself: CRCLOUDRACE_GAMEBIT_RACE_STARTED in crcloudrace.h */
    GAMEBIT_CF_SeqBit18049E = 0x49E,                     /* Named from map data alone - nothing in the code or in any name list mentions it: cloudrace/CFRaceSeqob objId= param=bit18; table 1 */
    GAMEBIT_CF_SeqBit18049F = 0x49F,                     /* Named from map data alone - nothing in the code or in any name list mentions it: cloudrace/CFRaceSeqob objId= param=bit18; cloudrace/CRSpellston objId= param=_20; table 1 */
    GAMEBIT_CloudRaceTotemGate = 0x4A0,                  /* The DLL names this one itself: CRCLOUDRACE_GAMEBIT_TOTEM_GATE in crcloudrace.h */
    GAMEBIT_CF_ObjGroups2 = 0x4A3,                       /* table 3; size 32 */
    GAMEBIT_CF_SeqBit1804A4 = 0x4A4,                     /* Named from map data alone - nothing in the code or in any name list mentions it: cloudrace/CFRaceSeqob objId= param=bit18; table 1 */
    GAMEBIT_LV_ObjGroups = 0x4A6,                        /* table 3; size 32 */
    GAMEBIT_WM_KrazSpirit1Returning = 0x4A7,             /* table 0; set when the spirit is visible */
    GAMEBIT_CloudRaceRaceCanFinish = 0x4A9,              /* The DLL names this one itself: CRCLOUDRACE_GAMEBIT_RACE_CAN_FINISH in crcloudrace.h */
    GAMEBIT_CF_GuardianParked = 0x4AA,                   /* The DLL names this one itself: GAMEBIT_CFGUARDIAN_PARKED in CFGuardian.c */
    GAMEBIT_WaterSpellStone1_4AB = 0x4AB,                /* table 1; related to spellstone */
    GAMEBIT_NW_ObjGroups = 0x4AE,                        /* table 3; size 32; also LinkB */
    GAMEBIT_AndrossRelated04B1 = 0x4B1,                  /* table 2; set when Andross's brain is defeated */
    GAMEBIT_MMP_FuelCell_4B2 = 0x4B2,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_SeqBit1A04B5 = 0x4B5,                     /* Named from map data alone - nothing in the code or in any name list mentions it: cloudrace/CFRaceSeqob objId= param=bit1A; table 1 */
    GAMEBIT_CF_SeqBit1804B6 = 0x4B6,                     /* Named from map data alone - nothing in the code or in any name list mentions it: cloudrace/CFRaceSeqob objId= param=bit18; table 1 */
    GAMEBIT_TargetRelated04B7 = 0x4B7,                   /* table 1; related to object targeting */
    GAMEBIT_CloudRaceTotemLatch = 0x4BA,                 /* The DLL names this one itself: CRCLOUDRACE_GAMEBIT_TOTEM_LATCH in crcloudrace.h */
    GAMEBIT_SC_StaffLeversDisabled = 0x4BD,              /* The exact complement of GAMEBIT_SC_StaffLeversEnabled - written 1 at every point that one is written 0 and 0 where it is written 1, so it presumably enables the levers' idle-state counterparts */
    GAMEBIT_CF_GuardianTalk2Complete = 0x4BE,            /* The DLL names this one itself: GAMEBIT_CFGUARDIAN_TALK_2_COMPLETE in CFGuardian.c */
    GAMEBIT_CF_Open04C0 = 0x4C0,                         /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFTreasureD objId= param=open; table 2 */
    GAMEBIT_CF_TreasureDClosedLatch04C1 = 0x4C1,         /* Read out of the retail placement data: fortress/CFTreasureD closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SC_CaptureWarpDone = 0x4D0,                  /* One-shot: once GAMEBIT_LV_CapturedByLightFoot appears, sc_levelcontrol latches this, opens swapcircle objgroup 2, warps to map 0x50 and closes objgroup 1, so the capture warp fires only once */
    GAMEBIT_WM_NpcItemUsed04D1 = 0x4D1,                  /* table 0; written in the same breath as GAMEBIT_WM_NpcItemUsed0310 when an item is used on the DLL 0x200 NPC */
    GAMEBIT_NW_FuelCell_4D2 = 0x4D2,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_IM_PushBlock_Placed = 0x4D3,                 /* table 2 */
    GAMEBIT_LV_FuelCell_4D4 = 0x4D4,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_LV_FuelCell_4D5 = 0x4D5,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_LV_FuelCell_4D6 = 0x4D6,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_LV_FuelCell_4D7 = 0x4D7,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_OFT_FuelCell_4D8 = 0x4D8,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_OFT_FuelCell_4D9 = 0x4D9,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_AllPowerBasesPowered = 0x4E0,             /* table 1; set after all three power-base bits are set */
    GAMEBIT_LINKF_FuelCell_4E1 = 0x4E1,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_TrickyPathRelated04E2 = 0x4E2,               /* table 3; pi_pathsearch reads it and throws the result away, immediately before checking a Tricky curve node's required and forbidden bits - so retail leaves no clue what it was for */
    GAMEBIT_TrickyTalk = 0x4E3,                          /* table 0; size 8; if < FF, can talk to Tricky, but he won't say anything */
    GAMEBIT_Tricky_Unlocked_Sidekick_Commands = 0x4E4,   /* table 2; DP names this Tricky_Unlocked_Sidekick_Commands; unlocks Tricky's sidekick command menu */
    GAMEBIT_Tricky_Spawns = 0x4E5,                       /* table 2; DP names this Tricky_Spawns; gates Tricky warp-helper/spawn placement */
    GAMEBIT_ITEM_SpellStone1_Used = 0x4E9,               /* table 2; hint 305 */
    GAMEBIT_Dll21BReset = 0x4EA,                         /* The DLL names this one itself: DLL_21B_RESET_BIT in 539.c */
    GAMEBIT_VFP_PodiumsActivated = 0x4EC,                /* Latched by VFP_LevelCo the first update both GAMEBIT_VFP_PodiumPrereq09B1 and ...09B2 are up; Rena has it driving param 0x22 on two temple VFP_PodiumP objects and a HitAnimator target. DLL 0x21B reads the same bit as its reached bit */
    GAMEBIT_Dll21BMoving = 0x4ED,                        /* The DLL names this one itself: DLL_21B_MOVING_BIT in 539.c */
    GAMEBIT_VFP_Lift1Ready = 0x4EE,                      /* The DLL names this one itself: VFPLIFT1_READY_GAMEBIT in 541.c */
    GAMEBIT_VFP_Lift1Toggle04F0 = 0x4F0,                 /* Read out of the retail placement data: temple/VFPLift1 toggleGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_VFP_Lift2Toggle04F3 = 0x4F3,                 /* Read out of the retail placement data: temple/VFPLift2 toggleGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_VFP_ClawDead4F4 = 0x4F4,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_ClawDead4F5 = 0x4F5,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_HitAnimTarget04F6 = 0x4F6,               /* Named from map data alone - nothing in the code or in any name list mentions it: temple/HitAnimator objId= param=target; table 2 */
    GAMEBIT_VFP_Open04F7 = 0x4F7,                        /* Named from map data alone - nothing in the code or in any name list mentions it: temple/SC_settelme objId= param=open; temple/StaffLeverO objId= param=activated; temple/CAMERAseqob objId= param=bit1A; table 2 */
    GAMEBIT_VFP_HitAnimTarget04F8 = 0x4F8,               /* Named from map data alone - nothing in the code or in any name list mentions it: temple/HitAnimator objId= param=target; table 2 */
    GAMEBIT_FoundSpellStoneWarpPad = 0x4FA,              /* table 2; hint 372; ref temple/HitAnimator target */
    GAMEBIT_VFP_ActNo = 0x4FE,                           /* table 2; size 4 */
    GAMEBIT_LINKF_FuelCell_4FF = 0x4FF,                  /* Rena's U0 dataset spells it "LI NKF_", a typo for the LINKF_FuelCell_ family; table 2 */
    GAMEBIT_VFP_ObjGroups = 0x500,                       /* table 3; size 32 */
    GAMEBIT_VFP_Param1E0503 = 0x503,                     /* Named from map data alone - nothing in the code or in any name list mentions it: temple/VFP_seqpoin objId= param=_1E; table 2 */
    GAMEBIT_VFP_Param1E0504 = 0x504,                     /* Named from map data alone - nothing in the code or in any name list mentions it: temple/VFP_seqpoin objId= param=_1E; table 2 */
    GAMEBIT_VFP_Lift1Gate0 = 0x507,                      /* The DLL names this one itself: VFPLIFT1_GATE_GAMEBIT_0 in 541.c */
    GAMEBIT_VFP_Lift1Gate1 = 0x508,                      /* The DLL names this one itself: VFPLIFT1_GATE_GAMEBIT_1 in 541.c */
    GAMEBIT_VFP_Lift1Gate2 = 0x509,                      /* The DLL names this one itself: VFPLIFT1_GATE_GAMEBIT_2 in 541.c */
    GAMEBIT_VFP_Lift1Gate3 = 0x50A,                      /* The DLL names this one itself: VFPLIFT1_GATE_GAMEBIT_3 in 541.c */
    GAMEBIT_CC_FuelCell_510 = 0x510,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_K1_ReturnPadGuard = 0x511,                   /* table 2; no traced setter */
    GAMEBIT_VFP_Activated0512 = 0x512,                   /* Named from map data alone - nothing in the code or in any name list mentions it: temple/VFP_flamepo objId= param=activated; temple/VFP_seqpoin objId= param=_1E; table 2 */
    GAMEBIT_VFP_Activated0513 = 0x513,                   /* Named from map data alone - nothing in the code or in any name list mentions it: temple/VFP_flamepo objId= param=activated; temple/VFP_seqpoin objId= param=_1E; table 2 */
    GAMEBIT_VFP_HitAnimTarget0514 = 0x514,               /* Named from map data alone - nothing in the code or in any name list mentions it: temple/HitAnimator objId= param=target; table 2 */
    GAMEBIT_VFP_RoundDoOpen0516 = 0x516,                 /* Read out of the retail placement data: temple/VFP_RoundDo openGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_AnimTest_ObjGroups = 0x517,                  /* table 3; size 32 */
    GAMEBIT_VFP_Lift2Toggle051E = 0x51E,                 /* Read out of the retail placement data: temple/VFPLift2 toggleGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_VFP_SeqBit180521 = 0x521,                    /* Named from map data alone - nothing in the code or in any name list mentions it: temple/CAMERAseqob objId= param=bit18; table 2 */
    GAMEBIT_VFP_DragHeadSpawnBlocked = 0x522,            /* While set, VFPDragHead returns from its spawn path before doing anything at all */
    GAMEBIT_CF_HitAnimTarget0526 = 0x526,                /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/HitAnimator objId= param=target; fortress/CFseqobject objId= param=bit1A; table 1 */
    GAMEBIT_CF_SeqBit180528 = 0x528,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFseqobject objId= param=bit18; table 1 */
    GAMEBIT_CC_FuelCell_52D = 0x52D,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_LINKF_FuelCell_52E = 0x52E,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_LINKF_FuelCell_52F = 0x52F,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_OFB_FuelCell_530 = 0x530,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_OFB_FuelCell_531 = 0x531,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_MMP_FuelCell_532 = 0x532,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_MMP_FuelCell_533 = 0x533,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_MMP_FuelCell_534 = 0x534,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_FuelCell_535 = 0x535,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_FuelCell_536 = 0x536,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_DIM_Entered540 = 0x540,                      /* table 1 */
    GAMEBIT_LINKB_Stage5Reached = 0x543,                 /* One of the five stages LINKB_levco's Tricky sequence resumes from - on load it walks them from 5 down to 1 and restarts at the highest one reached; the last stage, which LINKB_levco only ever reads */
    GAMEBIT_ITEM_TrickyStayFind_Got = 0x544,             /* table 2; hint 263 */
    GAMEBIT_CC_SeqUsed0545 = 0x545,                      /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/CCseqobj objId= param=usedBit; table 2 */
    GAMEBIT_CC_SeqUsed0546 = 0x546,                      /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/CCseqobj objId= param=usedBit; table 2 */
    GAMEBIT_TREX_ActNo = 0x547,                          /* table 1; size 4 */
    GAMEBIT_TREX_ObjGroups = 0x548,                      /* table 3; size 32 */
    GAMEBIT_DR_KTrexBranchState0 = 0x54A,                /* Galdon T-rex arena branch field 0, a 4-wide field rather than a flag; ktrexlevel_updatePathGameBits writes (2,2,1,1) across the four when GAMEBIT_DR_KTrexPathA is up and (1,1,2,2) for path B, and ktrexlevel_clearPathGameBits zeroes all four - there are as many of these as the arena has lanes, but nothing in the code pins a field to a lane */
    GAMEBIT_DR_KTrexBranchState1 = 0x54E,                /* Galdon T-rex arena branch field 1; takes the same value as field 0 in both path layouts */
    GAMEBIT_DR_KTrexBranchState2 = 0x552,                /* Galdon T-rex arena branch field 2; takes the value opposite fields 0 and 1 */
    GAMEBIT_DR_KTrexFootfallShake = 0x554,               /* table 0; raised at each of the three points K-Rex's footfalls enable the camera shake */
    GAMEBIT_DR_KTrexBranchState3 = 0x556,                /* Galdon T-rex arena branch field 3; moves with field 2 */
    GAMEBIT_DR_KTrexPathA = 0x55A,                       /* Dragon Rock K-Trex (Galdon) arena - path A active; toggles with 0x55b when a floor plate is charged to max, selecting which branch-path bits ktrexlevel applies */
    GAMEBIT_DR_KTrexPathB = 0x55B,                       /* Alternate branch-path selector for the Galdon T-rex arena (Dragon Rock); mutually exclusive with 0x55a, set when a floor switch's charge cycle maxes out and polled by ktrexlevel_updatePathGameBits to choose the arena's second path-bit layout */
    GAMEBIT_DR_LFXEmitterEnable055D = 0x55D,             /* Read out of the retail placement data: trexboss/LFXEmitter enableGameBit x1 */
    GAMEBIT_DR_KTrexArenaEnvReady = 0x55E,               /* Raised on the Galdon arena's first update tick, in the same breath as its sky slot flag, its three envfx and its light index */
    GAMEBIT_DR_SeqBit18055F = 0x55F,                     /* Named from map data alone - nothing in the code or in any name list mentions it: trexboss/KT_RexSeque objId= param=bit18; table 0 */
    GAMEBIT_DR_KTrexLane0Mode = 0x560,                   /* Dragon Rock K-Trex (Galdon) arena - lane 0 mode selector, gKTRexLaneModeGameBits[0]; ktrex_update ORs lane 0 into KTRexArenaState.laneMode only while the lane is in currentLaneMask and this bit is set */
    GAMEBIT_DR_KTrexLane1Mode = 0x561,                   /* Dragon Rock K-Trex (Galdon) arena - lane 1 mode selector, gKTRexLaneModeGameBits[1]; ktrex_update ORs lane 1 into KTRexArenaState.laneMode only while the lane is in currentLaneMask and this bit is set */
    GAMEBIT_DR_KTrexLane2Mode = 0x562,                   /* Dragon Rock K-Trex (Galdon) arena - lane 2 mode selector, gKTRexLaneModeGameBits[2]; ktrex_update ORs lane 2 into KTRexArenaState.laneMode only while the lane is in currentLaneMask and this bit is set */
    GAMEBIT_DR_KTrexLane3Mode = 0x563,                   /* Dragon Rock K-Trex (Galdon) arena - lane 3 mode selector, gKTRexLaneModeGameBits[3]; ktrex_update ORs lane 3 into KTRexArenaState.laneMode only while the lane is in currentLaneMask and this bit is set */
    GAMEBIT_WC_Unk0564 = 0x564,                          /* table 2 */
    GAMEBIT_DR_SeqBit180565 = 0x565,                     /* Named from map data alone - nothing in the code or in any name list mentions it: trexboss/KT_RexSeque objId= param=bit18; table 0 */
    GAMEBIT_DR_KTrexLane0Enabled = 0x566,                /* Dragon Rock K-Trex (Galdon) arena - lane 0 enabled, gKTRexLaneEnabledGameBits[0]; ktrex_update ORs lane 0 into KTRexArenaState.activeLaneMask when set; KT_RexLevel_init opens lanes 0 and 3 on arena entry */
    GAMEBIT_DR_KTrexLane1Enabled = 0x567,                /* Dragon Rock K-Trex (Galdon) arena - lane 1 enabled, gKTRexLaneEnabledGameBits[1]; ktrex_update ORs lane 1 into KTRexArenaState.activeLaneMask when set */
    GAMEBIT_DR_KTrexLane2Enabled = 0x568,                /* Dragon Rock K-Trex (Galdon) arena - lane 2 enabled, gKTRexLaneEnabledGameBits[2]; ktrex_update ORs lane 2 into KTRexArenaState.activeLaneMask when set */
    GAMEBIT_DR_KTrexLane3Enabled = 0x569,                /* Dragon Rock K-Trex (Galdon) arena - lane 3 enabled, gKTRexLaneEnabledGameBits[3]; ktrex_update ORs lane 3 into KTRexArenaState.activeLaneMask when set; KT_RexLevel_init opens lanes 0 and 3 on arena entry */
    GAMEBIT_DR_KTLazerwalIntensityBit056A = 0x56A,       /* Read out of the retail placement data through KtlazerwallPlacement.intensityBit: trexboss/KT_Lazerwal x4; trexboss/KT_RexFloor x2; trexboss/KT_Lazerlig x1; 7 placements. The struct is bound by the declared type of the variable the DLL reads the bit from, not guessed from what the DLL mentions; BITTABLE gives it a width of 4 bits, so it is a field rather than a flag */
    GAMEBIT_DR_KTLazerwalIntensityBit056B = 0x56B,       /* Read out of the retail placement data through KtlazerwallPlacement.intensityBit: trexboss/KT_Lazerwal x4; trexboss/KT_RexFloor x2; trexboss/KT_Lazerlig x1; 7 placements. The struct is bound by the declared type of the variable the DLL reads the bit from, not guessed from what the DLL mentions; BITTABLE gives it a width of 4 bits, so it is a field rather than a flag */
    GAMEBIT_DR_KTLazerwalIntensityBit056C = 0x56C,       /* Read out of the retail placement data through KtlazerwallPlacement.intensityBit: trexboss/KT_Lazerwal x4; trexboss/KT_RexFloor x2; trexboss/KT_Lazerlig x1; 7 placements. The struct is bound by the declared type of the variable the DLL reads the bit from, not guessed from what the DLL mentions; BITTABLE gives it a width of 4 bits, so it is a field rather than a flag */
    GAMEBIT_DR_KTLazerwalIntensityBit056D = 0x56D,       /* Read out of the retail placement data through KtlazerwallPlacement.intensityBit: trexboss/KT_Lazerwal x4; trexboss/KT_RexFloor x2; trexboss/KT_Lazerlig x1; 7 placements. The struct is bound by the declared type of the variable the DLL reads the bit from, not guessed from what the DLL mentions; BITTABLE gives it a width of 4 bits, so it is a field rather than a flag */
    GAMEBIT_DR_KTrexArenaEntered = 0x56E,                /* table 1; KT_RexLevel_init raises it while zeroing the phase counter, opening lanes 0 and 3 and selecting path A, and nothing clears it */
    GAMEBIT_DR_KTRexDoorPClosedLatch056F = 0x56F,        /* Read out of the retail placement data: trexboss/KT_RexDoorP closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DR_Open0570 = 0x570,                         /* Named from map data alone - nothing in the code or in any name list mentions it: trexboss/KT_RexDoorT objId= param=open; table 1 */
    GAMEBIT_DR_KTRexDoorTClosedLatch0571 = 0x571,        /* Read out of the retail placement data: trexboss/KT_RexDoorT closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DR_KTrexPhaseCounter = 0x572,                /* Dragon Rock K.Rex (Galdon) boss-arena phase/stage counter, advanced by the fight's state machine and read by DR floor switches (shifted right 1) to pick their rise curve */
    GAMEBIT_DR_KTLazerwalActiveBit0573 = 0x573,          /* Read out of the retail placement data through KtlazerwallPlacement.activeBit: trexboss/KT_Lazerwal x1; 1 placement. The struct is bound by the declared type of the variable the DLL reads the bit from, not guessed from what the DLL mentions */
    GAMEBIT_CF_SeqBit1A0574 = 0x574,                     /* Named from map data alone - nothing in the code or in any name list mentions it: clouddungeon/CFseqobject objId= param=bit1A; table 1 */
    GAMEBIT_ITEM_IMAlpineRoot_Count = 0x576,             /* table 2; size 3. Backs the collectable item C-menu entry the game labels "Alpine Root" (its owned bit) */
    GAMEBIT_ITEM_AlpineRoot_Used = 0x578,                /* table 2; size 3 */
    GAMEBIT_LINKE_FuelCell_57E = 0x57E,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_SC_SeqBit1A057F = 0x57F,                     /* Named from map data alone - nothing in the code or in any name list mentions it: swapcircle/SC_sequence objId= param=bit1A; table 0 */
    GAMEBIT_NW_AlpineroCollect0587 = 0x587,              /* Read out of the retail placement data: wastes/NW_alpinero collectGameBit x2; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_VFP_FuelCell_588 = 0x588,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_DFSH_ShrineIdle = 0x589,                     /* table 0; the Test of Combat shrine is idle and available - dropped the moment the player activates it, and put back at reset. DFSH_ObjCre reads it as its disable bit, which follows - the creator is off while the shrine is idle */
    GAMEBIT_NoMapData = 0x58D,                           /* table 0; Force No Map Data */
    GAMEBIT_Dll199Related0594 = 0x594,                   /* The DLL names this one itself: DLL199_GAMEBIT_0594 in 409.c */
    GAMEBIT_ITEM_MapVFP_Got = 0x59D,                     /* table 2; Have Volcano Force Point Map */
    GAMEBIT_ITEM_MapDIM_Got = 0x59E,                     /* table 2; Have DarkIce Mines Map */
    GAMEBIT_ITEM_MapNW_Got = 0x5A0,                      /* table 2; Have SnowHorn Wastes Map */
    GAMEBIT_ITEM_MapCF_Got = 0x5A1,                      /* table 2; Have CloudRunner Fortress Map */
    GAMEBIT_ITEM_MapLV_Got = 0x5A2,                      /* table 2; Have LightFoot Village Map */
    GAMEBIT_ITEM_MapSH_Got = 0x5A3,                      /* table 2; Have ThornTail Hollow Map */
    GAMEBIT_VFP_FuelCell_5A6 = 0x5A6,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_FuelCell_5AB = 0x5AB,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_GPSH_ResetSymbolCreators = 0x5AF,            /* Test of Knowledge reset latch; re-arms the six GPSH_ObjCre symbol spawners after success, timeout, or reset */
    GAMEBIT_LINKH_FuelCell_5B0 = 0x5B0,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_Dll199Related05B2 = 0x5B2,                   /* The DLL names this one itself: DLL199_GAMEBIT_05B2 in 409.c */
    GAMEBIT_Dll199Related05B5 = 0x5B5,                   /* The DLL names this one itself: DLL199_GAMEBIT_05B5 in 409.c */
    GAMEBIT_Dll19AReset = 0x5B9,                         /* DLL 0x19A calls it its reset bit while DLL 0x199 only has a placeholder for it */
    GAMEBIT_NW_SnowHown05BA = 0x5BA,                     /* table 0; related to riding SnowHorn */
    GAMEBIT_NW_SnowHown05BB = 0x5BB,                     /* table 0; related to riding SnowHorn */
    GAMEBIT_ITEM_OpenPortal_Got = 0x5BD,                 /* table 2; ref hollow/MagicCaveTo Collected. Backs the staff ability C-menu entry the game labels "Open Portal" (its owned bit) */
    GAMEBIT_DR_HitAnimTarget05BF = 0x5BF,                /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/HitAnimator objId= param=target; table 0 */
    GAMEBIT_DR_HitAnimTarget05C0 = 0x5C0,                /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/HitAnimator objId= param=target; table 0 */
    GAMEBIT_DR_CreatorSpawn05C7 = 0x5C7,                 /* Read out of the retail placement data: dragrock/DR_Creator spawnGameBit x2; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DR_CreatorSpawn05C8 = 0x5C8,                 /* Read out of the retail placement data: dragrock/DR_Creator spawnGameBit x2; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DR_HitAnimTarget05C9 = 0x5C9,                /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/HitAnimator objId= param=target; table 0 */
    GAMEBIT_ITEM_IceBlast_Got = 0x5CE,                   /* table 2; hint 302; ref temple/MagicCaveTo Collected. Backs the staff ability C-menu entry the game labels "Freeze Blast" (its owned bit) */
    GAMEBIT_KrazTest_ActNo = 0x5D0,                      /* table 1; size 4; also dfptop */
    GAMEBIT_KrazTest_ObjGroups = 0x5D1,                  /* table 3; size 32; also dfptop */
    GAMEBIT_DR_OnExplode05D2 = 0x5D2,                    /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/ExplodePlan objId= param=onExplode; table 2 */
    GAMEBIT_DR_HitAnimTarget05D3 = 0x5D3,                /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/HitAnimator objId= param=target; table 0 */
    GAMEBIT_LINKH_FuelCell_5D4 = 0x5D4,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_ITEM_FireflyNotShown_Count = 0x5D6,          /* table 2; size 5. FireFly calls it collect-count bit B, the partner of GAMEBIT_ITEM_Firefly_Count */
    GAMEBIT_DR_ObjGroups = 0x5DB,                        /* table 3; size 32 */
    GAMEBIT_DRBOT_ObjGroups = 0x5DC,                     /* table 3; size 32 */
    GAMEBIT_DR_CreatorInitClear = 0x5DD,                 /* DR_Creator clears it at init, which is all its own alias claimed for it */
    GAMEBIT_OFP_SparkPrereqA05E0 = 0x5E0,                /* table 0; one of the two halves GAMEBIT_OFP_SparkLatch05E3 waits on */
    GAMEBIT_OFP_SparkPrereqB05E1 = 0x5E1,                /* table 0; the other half of GAMEBIT_OFP_SparkLatch05E3's pair */
    GAMEBIT_OFP_TorchSequenceStage2 = 0x5E2,             /* Raised as the DFP torch sequence reaches its stage 2, when the second-colour torch's own placement bit comes up */
    GAMEBIT_OFP_SparkLatch05E3 = 0x5E3,                  /* Spark latch: DFP_LevelCo plays SFXTRIG_wp_espk2_c and latches it the first update both halves of its pair are up; the check runs in both the act 1 and act 2 paths */
    GAMEBIT_OFP_PuzzlePadShowSolution = 0x5E4,           /* Ocean Force Point electric-floor solution display is active while the puzzle pad is pressed */
    GAMEBIT_OFP_ZappedByFloorTiles = 0x5E5,              /* player stepped on an electrified Ocean Force Point floor tile */
    GAMEBIT_OFP_LeverLatch05E8 = 0x5E8,                  /* Latched once both GAMEBIT_OFP_LeverPrereqA05EE and ...B05EF are up; Rena has it as kraztest StaffLeverO 0x4C796's activated param and a HitAnimator target, so the lever reads as pulled from then on */
    GAMEBIT_OFP_LeverPrereqA05EE = 0x5EE,                /* table 0; one of the two halves GAMEBIT_OFP_LeverLatch05E8 waits on */
    GAMEBIT_OFP_LeverPrereqB05EF = 0x5EF,                /* table 0; the other half of GAMEBIT_OFP_LeverLatch05E8's pair */
    GAMEBIT_OFB_Open05F0 = 0x5F0,                        /* Named from map data alone - nothing in the code or in any name list mentions it: kraztest/DFP_Bridge objId= param=open; table 2 */
    GAMEBIT_OFB_SfxPlayerBit05F1 = 0x5F1,                /* Read out of the retail placement data: kraztest/sfxPlayer gameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_ITEM_SpellStone2_Used = 0x5F3,               /* table 2; hint 342 */
    GAMEBIT_ITEM_SpellStone4_Used = 0x5F4,               /* table 2; hint 405 */
    GAMEBIT_NW_FuelCell_5F7 = 0x5F7,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_LINKE_FuelCell_5F8 = 0x5F8,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_ITEM_DeletedSpell5FC_Got = 0x5FC,            /* table 2; in spell bits table but does nothing */
    GAMEBIT_LINKH_FuelCell_600 = 0x600,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_SHOP_ObjGroups = 0x601,                      /* table 3; size 32 */
    GAMEBIT_OFT_FuelCell_602 = 0x602,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_OFT_FuelCell_603 = 0x603,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_FuelCell_604 = 0x604,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_DR_WallExploded0605 = 0x605,                 /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/ExplodePlan objId= param=exploded; dragrock/ExplodePlan objId= param=collected; table 2 */
    GAMEBIT_DR_LeverActivated0606 = 0x606,               /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/StaffLeverO objId= param=activated; table 0 */
    GAMEBIT_DR_RescuedCloudRunner = 0x609,               /* table 2; hint 393; ref dragrock/HitAnimator target */
    GAMEBIT_VFP_FuelCell_60D = 0x60D,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_SC_TotemRunRequest060E = 0x60E,              /* Raised by the controller's anim event 3 and consumed on the next update: outside a run it opens the best-times list, and during a run it stops the timer, raises the hit-animator target and starts the exit fade */
    GAMEBIT_SC_TotemCircleRelated060F = 0x60F,           /* Held at 1 through init and every update; the sole write of 0 is at the top of the anim-event callback, which restores it immediately when the controller is mid-run, so it is only ever clear for the frame after an event arrives out of run */
    GAMEBIT_ITEM_MMPKey_Got = 0x611,                     /* table 2; ref moonpass/MMP_padlock key. Backs the collectable item C-menu entry the game labels "Use Key" (its owned bit) */
    GAMEBIT_SC_LVBlock2Related0612 = 0x612,              /* One of the three bits sc_levelcontrol raises the moment GAMEBIT_ITEM_LVBlock2_Used is set; Rena has this one as the target of swapcircle's HitAnimator 0x45D72 */
    GAMEBIT_SC_SteppingClosedLatch0613 = 0x613,          /* Read out of the retail placement data: swapcircle/SC_stepping closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_LV_FuelCell_615 = 0x615,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_LV_FuelCell_616 = 0x616,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_SHOP_Unk0617 = 0x617,                        /* table 0; set when entering shop */
    GAMEBIT_LV_DoneTests = 0x61C,                        /* table 2; hint 349 */
    GAMEBIT_ShopKeeperHasMoney = 0x61D,                  /* The shopkeeper DLL calls it his has-money bit; Rena had it only as ShopRelated61D */
    GAMEBIT_CC_GasVentControlPuzzleState = 0x620,        /* The DLL names this one itself: CC_GAS_VENT_CONTROL_PUZZLE_STATE_GAMEBIT in CCgasventCo.c */
    GAMEBIT_ShopKeeperScarabGameWon = 0x624,             /* The shopkeeper's scarab game was won, per that DLL's own alias */
    GAMEBIT_ShopKeeperScarabGameLost = 0x625,            /* The shopkeeper's scarab game was lost, the counterpart to GAMEBIT_ShopKeeperScarabGameWon */
    GAMEBIT_SHOP_ScarabGameRunning = 0x626,              /* table 0; ref swapstore/HitAnimator target */
    GAMEBIT_LV_ChiefTestDone0627 = 0x627,                /* The half of GAMEBIT_LV_DoneTests' condition that sc_levelcontrol only reads - the LightFoot chief's other test, completed outside this DLL */
    GAMEBIT_DR_HighTop_RunSeq = 0x62A,                   /* table 1; name from Rena's kiosk-build data, confirmed by the code - hightop_stateHandler04 sets it the moment all four of GAMEBIT_DR_HighTopSwitch1-4 are hit */
    GAMEBIT_DR_HighTop_SeqDone = 0x62B,                  /* table 1; kiosk-build name - while set, HighTop sets GAMEBIT_DR_HighTop_SeqDone2, arms its curve-follow ride and starts the air meter */
    GAMEBIT_DR_HighTopRelated062C = 0x62C,               /* Read once by HighTop, to drop its runtime into substate 2 */
    GAMEBIT_DR_HighTop_Riding62D = 0x62D,                /* Rena's kiosk dataset; table 1 */
    GAMEBIT_DR_HighTop_SeqDone2 = 0x62F,                 /* table 1; kiosk-build name - raised by HighTop as it begins the ride */
    GAMEBIT_DR_HighTop_Riding630 = 0x630,                /* table 1; kiosk-build name - HighTop's substate 0xA hands control to the riding state while it is set */
    GAMEBIT_DR_HighTopRideOver = 0x631,                  /* HighTop's ride is over - DR_Creator and HighTop's own case 7 raise it, and two of HighTop's state handlers send the object straight to state 8 while it is up */
    GAMEBIT_DR_RescuedHighTop = 0x632,                   /* table 2; hint 391; ref dragrock/HitAnimator target */
    GAMEBIT_DR_HighTopRideStarted = 0x634,               /* Raised as HighTop's case 6 runs its sequence 4 and dropped both by case 7 and when the air meter empties, so it stands for the ride being under way */
    GAMEBIT_OFP_PuzzlePadPressed = 0x635,                /* Ocean Force Point electric-floor puzzle pad is pressed */
    GAMEBIT_SC_totempuzzle_running = 0x639,              /* table 2 */
    GAMEBIT_ITEM_SpellStone3_Got = 0x63C,                /* table 2; hint 373 */
    GAMEBIT_SC_TotemRunCompleted = 0x63E,                /* A timed totem run carried through to its fade-out, as against GAMEBIT_SC_TimedRunExited for the exit path; with GAMEBIT_LV_ChiefTestDone0627 it is what raises GAMEBIT_LV_DoneTests, making it one of the chief's two tests */
    GAMEBIT_SC_SeqBit18063F = 0x63F,                     /* Named from map data alone - nothing in the code or in any name list mentions it: swapcircle/SC_sequence objId= param=bit18; table 2 */
    GAMEBIT_SC_TimedRunExited = 0x640,                   /* Raised when a timed totem run ends down the exit path instead of the fade-out - the run's other ending */
    GAMEBIT_SC_SeqBit180641 = 0x641,                     /* Named from map data alone - nothing in the code or in any name list mentions it: swapcircle/SC_sequence objId= param=bit18; table 2 */
    GAMEBIT_TumbleweedRelated642 = 0x642,                /* table 0 */
    GAMEBIT_PlayerTouchedSurface31 = 0x643,              /* Raised by the player's surface handler for surface type 31 and nothing else */
    GAMEBIT_ITEM_LVBlock2_Used = 0x647,                  /* table 2; ref swapcircle/SC_blockpla open. Backs the collectable item C-menu entry the game labels "Place Block" (its used bit) */
    GAMEBIT_DRBOT_SeqBit180649 = 0x649,                  /* Named from map data alone - nothing in the code or in any name list mentions it: dragbot/DR_SeqobjBo objId= param=bit18; table 0 */
    GAMEBIT_SH_Landed064B = 0x64B,                       /* table 0; set when Fox first steps foot on the planet; cleared after Pepper scene */
    GAMEBIT_Dll1B5CompletionSCTotemBond = 0x64C,         /* The DLL names this one itself: DLL1B5_COMPLETION_GAMEBIT_SC_TOTEM_BOND in 437.h */
    GAMEBIT_SC_TotemBondRing0 = 0x64D,                   /* LightFoot Village totem-bond puzzle - ring slot 0 bonded, gTotemBondRingGameBits[0]; set to 1 when the ring is bonded and passed as the spawned orb's activeGameBit */
    GAMEBIT_SC_TotemBondRing1 = 0x64E,                   /* LightFoot Village totem-bond puzzle - ring slot 1 bonded, gTotemBondRingGameBits[1]; set to 1 when the ring is bonded and passed as the spawned orb's activeGameBit */
    GAMEBIT_SC_TotemBondRing2 = 0x64F,                   /* LightFoot Village totem-bond puzzle - ring slot 2 bonded, gTotemBondRingGameBits[2]; set to 1 when the ring is bonded and passed as the spawned orb's activeGameBit */
    GAMEBIT_SC_TotemBondRing3 = 0x650,                   /* LightFoot Village totem-bond puzzle - ring slot 3 bonded, gTotemBondRingGameBits[3]; set to 1 when the ring is bonded and passed as the spawned orb's activeGameBit */
    GAMEBIT_ITEM_DinoHorn_651 = 0x651,                   /* table 2 */
    GAMEBIT_DIM_ClawDead652 = 0x652,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_DRBOT_HoverPadRelated0660 = 0x660,           /* The Drakor hover pad's curve carries event codes, and this is one of the bits DLL 625 writes as the pad runs them - code 4 raises it when the pad's b40 flag is up */
    GAMEBIT_DRBOT_HoverPadRouteOpen = 0x661,             /* The Drakor hover pad's route ahead is open: codes 4 and 9 both bring the pad to a dead stop, zeroing its commanded speed, whenever this is clear */
    GAMEBIT_ITEM_BombSpore_Count = 0x66C,                /* table 2; size 3. Backs the collectable item C-menu entry the game labels "Plant Bomb Spore" (its owned bit) */
    GAMEBIT_ITEM_WhiteShroom_Count = 0x66D,              /* table 2; size 3. Backs the collectable item C-menu entry the game labels "Feed to Queen" (its owned bit) */
    GAMEBIT_DFP_Statue1VariantA = 0x66E,                 /* The DLL names this one itself: GAMEBIT_DFP_STATUE1_VARIANT_A in DFP_Statue1.c */
    GAMEBIT_DFP_Statue1VariantB = 0x66F,                 /* The DLL names this one itself: GAMEBIT_DFP_STATUE1_VARIANT_B in DFP_Statue1.c */
    GAMEBIT_DFP_Statue1VariantC = 0x670,                 /* The DLL names this one itself: GAMEBIT_DFP_STATUE1_VARIANT_C in DFP_Statue1.c */
    GAMEBIT_OFB_LeverActivated0671 = 0x671,              /* Named from map data alone - nothing in the code or in any name list mentions it: kraztest/StaffLeverO objId= param=activated; kraztest/VFP_flamepo objId= param=activated; table 0 */
    GAMEBIT_DRBOT_HoverPadReverse = 0x676,               /* The Drakor hover pad's reverse bit: the pad caches its last value and negates its commanded speed the moment the two disagree, which is the polling the DLL's own header comment describes */
    GAMEBIT_DRBOT_HoverPadLeverActivated = 0x67F,        /* Rena has it as dragbot StaffLeverT 0x45C6A's activated param and the target of two HitAnimators; the hover pad's code 8 does nothing but report its state back to the curve */
    GAMEBIT_OFB_HitAnimTarget0681 = 0x681,               /* Named from map data alone - nothing in the code or in any name list mentions it: kraztest/DFP_RoundDo objId= param=open; kraztest/HitAnimator objId= param=target; kraztest/HitAnimator objId= param=target; table 2 */
    GAMEBIT_DRBOT_HitAnimTarget0687 = 0x687,             /* Named from map data alone - nothing in the code or in any name list mentions it: dragbot/ExplodeWall objId= param=exploded; dragbot/HitAnimator objId= param=target; dragbot/HitAnimator objId= param=target (+1 more); table 1 */
    GAMEBIT_DRBOT_HoverPadRelated0689 = 0x689,           /* The Drakor hover pad's curve carries event codes, and this is one of the bits DLL 625 writes as the pad runs them - code 10 latches it once, and checks it first so it fires only the first time the pad passes */
    GAMEBIT_DRBOT_HoverPadRidden068A = 0x68A,            /* The Drakor hover pad's curve carries event codes, and this is one of the bits DLL 625 writes as the pad runs them - code 11 raises it only while the player is actually parented to the pad, and code 13 needs it before it will double-bounce */
    GAMEBIT_DRBOT_HoverPadRidden068B = 0x68B,            /* The Drakor hover pad's curve carries event codes, and this is one of the bits DLL 625 writes as the pad runs them - code 12's counterpart to GAMEBIT_DRBOT_HoverPadRidden068A, again only while the player is riding */
    GAMEBIT_LanternFireflyActiveCount = 0x698,           /* A count, not a flag: LanternFire runs gameBitIncrement and gameBitDecrement on it as its fireflies come and go. DLL 211 reads the same bit as a plain boolean to reverse the landed Arwing's chase direction, and had named it for that */
    GAMEBIT_TTH_BafomDad_69C = 0x69C,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_TTH_BafomDad_69D = 0x69D,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_TTH_BafomDad_69E = 0x69E,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_BafomDad_6A1 = 0x6A1,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_CD_BafomDad_6A2 = 0x6A2,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_BafomDad_6A5 = 0x6A5,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_CD_BafomDad_6A6 = 0x6A6,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_KP_BafomDad_6A9 = 0x6A9,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_BafomDad_6AD = 0x6AD,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_CC_BafomDad_6AE = 0x6AE,                     /* accidentally assigned to 2 BafomDads; Rena's U0 dataset; table 2 */
    GAMEBIT_CC_BafomDad_6B1 = 0x6B1,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_DR_BafomDad_6B2 = 0x6B2,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_DR_BafomDad_6B3 = 0x6B3,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_NW_BafomDad_6B4 = 0x6B4,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_NW_BafomDad_6B5 = 0x6B5,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_NW_BafomDad_6B6 = 0x6B6,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_NW_BafomDad_6B7 = 0x6B7,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_MMP_BafomDad_6D1 = 0x6D1,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_NW_FuelCell_6D5 = 0x6D5,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_WC_BafomDad_6D6 = 0x6D6,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_WC_BafomDad_6D7 = 0x6D7,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_WC_BafomDad_6D8 = 0x6D8,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_WC_BafomDad_6D9 = 0x6D9,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_SH_LargeCrateBroken06DB = 0x6DB,             /* Read out of the retail placement data: hollow/LargeCrate brokenGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_OFB_BafomDad_6E9 = 0x6E9,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_OFB_BafomDad_6EA = 0x6EA,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_TTH_BafomDad_6FF = 0x6FF,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_WM_Bafomdad1_Got = 0x703,                    /* table 2; hidden passage at start */
    GAMEBIT_CF_BafomDad_704 = 0x704,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_BafomDad_707 = 0x707,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_LV_BafomDad_70B = 0x70B,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_LV_BafomDad_70C = 0x70C,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_LINKF_BafomDad_70F = 0x70F,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_LINKF_BafomDad_710 = 0x710,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_CC_BafomDad_713 = 0x713,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_MMP_BafomDad_733 = 0x733,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_MMP_BafomDad_734 = 0x734,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_MMP_BafomDad_736 = 0x736,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_OFB_BafomDad_750 = 0x750,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_DRBOT_WallExploded0764 = 0x764,              /* Named from map data alone - nothing in the code or in any name list mentions it: dragbot/ExplodePlan objId= param=exploded; dragbot/ExplodePlan objId= param=collected; table 1 */
    GAMEBIT_DRBOT_HitAnimTarget0765 = 0x765,             /* Named from map data alone - nothing in the code or in any name list mentions it: dragbot/StaffLeverT objId= param=enabled; dragbot/StaffLeverT objId= param=enabled; dragbot/DR_SeqobjBo objId= param=bit1A (+11 more); table 1 */
    GAMEBIT_OFB_StaffBoost_766 = 0x766,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_SC_TotemBondOrb0 = 0x768,                    /* LightFoot Village totem-bond puzzle - orb slot 0 consumed, gTotemBondOrbGameBits[0]; the spawned orb's eventGameBit, and slot 0 counts as still available while this reads 0 */
    GAMEBIT_SC_TotemBondOrb1 = 0x769,                    /* LightFoot Village totem-bond puzzle - orb slot 1 consumed, gTotemBondOrbGameBits[1]; the spawned orb's eventGameBit, and slot 1 counts as still available while this reads 0 */
    GAMEBIT_SC_TotemBondOrb2 = 0x76A,                    /* LightFoot Village totem-bond puzzle - orb slot 2 consumed, gTotemBondOrbGameBits[2]; the spawned orb's eventGameBit, and slot 2 counts as still available while this reads 0 */
    GAMEBIT_SC_TotemBondOrb3 = 0x76B,                    /* LightFoot Village totem-bond puzzle - orb slot 3 consumed, gTotemBondOrbGameBits[3]; the spawned orb's eventGameBit, and slot 3 counts as still available while this reads 0 */
    GAMEBIT_DR_ActNo = 0x76E,                            /* table 1; size 4 */
    GAMEBIT_DRBOT_ActNo = 0x76F,                         /* table 1; size 4 */
    GAMEBIT_ITEM_DeletedSpell777_Got = 0x777,            /* table 2; in spell bits table but does nothing */
    GAMEBIT_TimeListPromptDeclined = 0x781,              /* The best-times prompt was answered with anything other than its first option - see GAMEBIT_TimeListPromptAccepted */
    GAMEBIT_SC_SeqBit180782 = 0x782,                     /* Named from map data alone - nothing in the code or in any name list mentions it: swapcircle/SC_sequence objId= param=bit18; table 2 */
    GAMEBIT_SC_TotemStrengthWon = 0x784,                 /* The DLL names this one itself: SC_TOTEM_STRENGTH_GAMEBIT_WON in SC_totemstr.c */
    GAMEBIT_SC_SeqBit180785 = 0x785,                     /* Named from map data alone - nothing in the code or in any name list mentions it: swapcircle/SC_sequence objId= param=bit18; table 2 */
    GAMEBIT_SC_TotemStrengthLost = 0x786,                /* The DLL names this one itself: SC_TOTEM_STRENGTH_GAMEBIT_LOST in SC_totemstr.c */
    GAMEBIT_SC_SeqBit180787 = 0x787,                     /* Named from map data alone - nothing in the code or in any name list mentions it: swapcircle/SC_sequence objId= param=bit18; table 2 */
    GAMEBIT_DRBOT_HoverPadHalted = 0x788,                /* Raised at both points DLL 625 brings the hover pad to a halt: code 4 with the route closed, and code 15 with the pad's b40 flag down */
    GAMEBIT_WallCrawlerSpeedLevel = 0x789,               /* table 1; a speed level, not a flag: the wall crawler reads it straight into its speed cap as 0.1 * level + 0.1 */
    GAMEBIT_OFP_SparkLatch0792 = 0x792,                  /* The same spark latch shape as GAMEBIT_OFP_SparkLatch05E3, but waiting on GAMEBIT_OFB_PinPonDeadB8C - which retail tests twice in the one condition */
    GAMEBIT_OFP_LoadBlockSlidePuzzle2 = 0x7A1,           /* loads Ocean Force Point object group 6, the lower block-slide puzzle */
    GAMEBIT_DR_HighTop_JumpingOn = 0x7A4,                /* Rena's kiosk dataset; table 1 */
    GAMEBIT_OFB_HitAnimTarget07A7 = 0x7A7,               /* Named from map data alone - nothing in the code or in any name list mentions it: kraztest/HitAnimator objId= param=target; kraztest/HitAnimator objId= param=target; table 2 */
    GAMEBIT_OFB_StaffBoostEnabled7A8 = 0x7A8,            /* Rena's U0 dataset; table 2 */
    GAMEBIT_DR_CloudRunnerCurveSlot = 0x7A9,             /* table 1; a stored curve slot, not a flag: a spawning CloudRunner reads it and, if non-zero, places itself at curve action target slot + 0x13. DR_CloudPer names it the active-cloud bit, which fits a stored slot */
    GAMEBIT_DR_CloudRunnerAirTime = 0x7AA,               /* table 1; a stored value: DR_CloudRunner_free writes its remaining air time straight into it, and DLL 620 seeds it with 5 */
    GAMEBIT_SeqBit1807AD = 0x7AD,                        /* Named from map data alone - nothing in the code or in any name list mentions it: finalboss/BossDrakor_ objId= param=bit18; table 0 */
    GAMEBIT_SeqBit1A07AE = 0x7AE,                        /* Named from map data alone - nothing in the code or in any name list mentions it: finalboss/BossDrakor_ objId= param=bit1A; table 0 */
    GAMEBIT_SeqBit1A07AF = 0x7AF,                        /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/DR_Seqobj objId= param=bit1A; finalboss/BossDrakor_ objId= param=bit18; table 2 */
    GAMEBIT_DRBOT_HoverPadRelated07BA = 0x7BA,           /* The Drakor hover pad's curve carries event codes, and this is one of the bits DLL 625 writes as the pad runs them - raised by code 2 and read nowhere in the code */
    GAMEBIT_DR_EarthWarriorUnknown_2 = 0x7BC,            /* set by DR_EarthWar.c when mounted and cleared when dismounted */
    GAMEBIT_ITEM_SpellStone7BD_Got = 0x7BD,              /* table 2; unused?. Backs the collectable item C-menu entry the game labels "Use SpellStone" (its owned bit) */
    GAMEBIT_OFB_Open07BE = 0x7BE,                        /* Named from map data alone - nothing in the code or in any name list mentions it: kraztest/DFP_RoundDo objId= param=open; kraztest/StaffLeverO objId= param=activated; kraztest/CAMERAseqob objId= param=bit1A (+1 more); table 2 */
    GAMEBIT_ITEM_SpellStone7BF_Got = 0x7BF,              /* table 1. Backs the collectable item C-menu entry the game labels "Use SpellStone" (its owned bit) */
    GAMEBIT_OFB_DFPseqpoinDisable07C1 = 0x7C1,           /* A DFP sequence point's disable bit, from its placement's field at 0x20. Two of the ids that slot holds - 0xCB1 and 0xEE0 - were already named from other evidence, which is what vindicates the slot; DfpSeqPointPlacement overruns the 0x24 record at its tail, but this field is inside it */
    GAMEBIT_OFP_Reopened = 0x7C2,                        /* table 2; hint 403; ref dfptop/HitAnimator target */
    GAMEBIT_HT_ObjStates = 0x7CE,                        /* table 3; size 32 */
    GAMEBIT_SC_TotemRunRelated07CF = 0x7CF,              /* Raised beside GAMEBIT_SC_TotemRunCompleted on the fade-out path and nowhere else, with nothing in the code reading it back */
    GAMEBIT_DR_EarthWarriorUnknown_3 = 0x7D4,            /* cleared by DR_EarthWar.c when mounted and set when dismounted */
    GAMEBIT_ITEM_MapDR_Got = 0x7DD,                      /* table 2 */
    GAMEBIT_ITEM_MapWM_Got = 0x7E5,                      /* table 2 */
    GAMEBIT_ITEM_MapOFP_Got = 0x7E9,                     /* table 2 */
    GAMEBIT_WC_TimedPuzzleATrigger = 0x7ED,              /* Walled City timed push-block puzzle A - entry trigger; wclevelcont polls it in the default mode and, while PUZZLE_A is unfinished, arms the puzzle by setting GAMEBIT_WC_TimedPuzzleAActive and a 70-unit event timer */
    GAMEBIT_WC_TimedPuzzleBTrigger = 0x7EE,              /* Walled City timed push-block puzzle B - entry trigger; mirrors puzzle A, arming GAMEBIT_WC_TimedPuzzleBActive */
    GAMEBIT_WC_TimedPuzzleAActive = 0x7EF,               /* Walled City timed push-block puzzle A - armed/running; set by wclevelcont when the trigger fires and cleared on timeout or abort */
    GAMEBIT_WC_TimedPuzzleBActive = 0x7F0,               /* Walled City timed push-block puzzle B - armed/running; cleared on timeout or abort */
    GAMEBIT_WC_IsNight = 0x7F1,                          /* Walled City is in its night state - wclevelcont writes it and GAMEBIT_WC_IsDay as a complementary pair off the sky interface's sun position every update */
    GAMEBIT_WC_TempleDooClosedLatch07F2 = 0x7F2,         /* Read out of the retail placement data: wallcity/WCTempleDoo closedLatchGameBit x2; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_WC_IsDay = 0x7F3,                            /* Walled City is in its day state; the complement of GAMEBIT_WC_IsNight */
    GAMEBIT_WC_TempleDooClosedLatch07F4 = 0x7F4,         /* Read out of the retail placement data: wallcity/WCTempleDoo closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_WC_TimedPuzzleAComplete = 0x7F7,             /* Walled City timed push-block puzzle A fully complete; wclevelcont_seqFn sets it once A's post-solve sequence timer runs out and saves a checkpoint at the player */
    GAMEBIT_WC_LitBeacons = 0x7F8,                       /* table 2; hint 362; ref wallcity/HitAnimator target */
    GAMEBIT_WC_TimedPuzzleASolved = 0x7F9,               /* Walled City timed push-block puzzle A solved; ends the 0x3C countdown, and if puzzle B is also solved wclevelcont plays the confirm sfx and runs sequence 0 instead of sequence 1 */
    GAMEBIT_WC_TimedPuzzleBSolved = 0x7FA,               /* Walled City timed push-block puzzle B solved; ends the 0x50 countdown, and pairs with puzzle A to pick the confirm sfx and sequence 0 */
    GAMEBIT_WC_EarthWalkerTalked = 0x7FB,                /* Raised the first time the player activates the Walled City EarthWalker; Rena has it as wallcity HitAnimator 0x4B707's target */
    GAMEBIT_WC_FoundKing = 0x7FC,                        /* table 2; hint 363 */
    GAMEBIT_WC_TimedPuzzleBComplete = 0x802,             /* Walled City timed push-block puzzle B fully complete; the puzzle-B mirror of 0x7F7, also saving a checkpoint */
    GAMEBIT_MMP_SeqBit1A0803 = 0x803,                    /* Named from map data alone - nothing in the code or in any name list mentions it: moonpass/MMP_seqobje objId= param=bit1A; table 0 */
    GAMEBIT_MMP_SeqBit180804 = 0x804,                    /* Named from map data alone - nothing in the code or in any name list mentions it: moonpass/MMP_seqobje objId= param=bit18; table 2 */
    GAMEBIT_WC_PushBlockAFade = 0x808,                   /* Push-block puzzle A's fade flag, aliased locally in dll_0290_wcpushblock.h as WCPUSHBLOCK_GAMEBIT_A_FADE. WCTile names the same bit its own tile-A fade */
    GAMEBIT_WC_PushBlockBFade = 0x809,                   /* Push-block puzzle B's fade flag (WCPUSHBLOCK_GAMEBIT_B_FADE). WCTile names the same bit its own tile-B fade */
    GAMEBIT_MMP_SeqBit1A080B = 0x80B,                    /* Named from map data alone - nothing in the code or in any name list mentions it: moonpass/MMP_seqobje objId= param=bit1A; table 0 */
    GAMEBIT_MMP_SeqBit18080C = 0x80C,                    /* Named from map data alone - nothing in the code or in any name list mentions it: moonpass/MMP_seqobje objId= param=bit18; table 2 */
    GAMEBIT_OFB_Open080F = 0x80F,                        /* Named from map data alone - nothing in the code or in any name list mentions it: kraztest/DFP_RoundDo objId= param=open; table 2 */
    GAMEBIT_WC_PushBlockACount = 0x810,                  /* How many of push-block puzzle A's four blocks are placed - a counter, not a flag: wclevelcont marks the puzzle solved when it reads 4, and clears it on reset and at init beside restoring gWcTileGridA */
    GAMEBIT_WC_PushBlockBCount = 0x811,                  /* Push-block puzzle B's placed-block count, the counterpart to GAMEBIT_WC_PushBlockACount */
    GAMEBIT_WC_PushBlockASolved = 0x812,                 /* Push-block puzzle A solved, which wclevelcont_init reads back into WCLEVELCTL_FLAG_TILE_A; two DLLs alias it locally from either end - WCPUSHBLOCK_GAMEBIT_A_SOLVED for the cause and WCTILE_GAMEBIT_A_HIDE for its effect on the tiles */
    GAMEBIT_WC_PushBlockBSolved = 0x813,                 /* Push-block puzzle B solved (WCPUSHBLOCK_GAMEBIT_B_SOLVED / WCTILE_GAMEBIT_B_HIDE), read back into WCLEVELCTL_FLAG_TILE_B */
    GAMEBIT_WC_Open0814 = 0x814,                         /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCGeneralDo objId= param=open; table 2 */
    GAMEBIT_WC_Open0815 = 0x815,                         /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCGeneralDo objId= param=open; table 2 */
    GAMEBIT_WC_HitAnimTarget0816 = 0x816,                /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/HitAnimator objId= param=target; table 2 */
    GAMEBIT_WC_OpenedSunMoonAreas = 0x817,               /* table 2; hint 410; ref wallcity/HitAnimator target */
    GAMEBIT_WC_FlewTo = 0x818,                           /* table 2; hint 360; ref wallcity/Landed_Arwi Visible */
    GAMEBIT_WC_OpenedBossDoor = 0x819,                   /* table 2; hint 365; ref wallcity/HitAnimator target */
    GAMEBIT_WC_WarpEnabled81B = 0x81B,                   /* Rena's U0 dataset; table 2 */
    GAMEBIT_TREX_WarpEnabled81C = 0x81C,                 /* Rena's U0 dataset; table 2 */
    GAMEBIT_ITEM_WCSilverTooth_Got = 0x81D,              /* table 2; ref wallcity/TreasureChe item. Backs the collectable item C-menu entry the game labels "Use Silver Tooth" (its owned bit) */
    GAMEBIT_ITEM_WCGoldTooth_Got = 0x81E,                /* table 2; ref wallcity/TreasureChe item. Backs the collectable item C-menu entry the game labels "Use Gold Tooth" (its owned bit) */
    GAMEBIT_DR_SeqNeed0822 = 0x822,                      /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/CAMERAnewse objId= param=needBit; table 0 */
    GAMEBIT_WC_SeqBit1A0828 = 0x828,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit1A; table 2 */
    GAMEBIT_WC_SeqBit1A0829 = 0x829,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit1A; table 2 */
    GAMEBIT_ITEM_MapWC_Got = 0x82E,                      /* table 2 */
    GAMEBIT_ITEM_MapCC_Got = 0x82F,                      /* table 2 */
    GAMEBIT_ITEM_MapMMP_Got = 0x835,                     /* table 2 */
    GAMEBIT_ITEM_SpellStone83A_Got = 0x83A,              /* table 2; unused?. Backs the collectable item C-menu entry the game labels "Use SpellStone" (its owned bit) */
    GAMEBIT_ITEM_FireSpellStone2_Got = 0x83B,            /* table 2; hint 369; ref temple/VFP_PodiumP key. Backs the collectable item C-menu entry the game labels "Use SpellStone" (its owned bit) */
    GAMEBIT_ITEM_WaterSpellStone2_Got = 0x83C,           /* table 2; hint 401; ref dfptop/VFP_PodiumP key. Backs the collectable item C-menu entry the game labels "Use SpellStone" (its owned bit) */
    GAMEBIT_MMP_MSBushPlanted0849 = 0x849,               /* Read out of the retail placement data: moonpass/MSBush plantedGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSBushGrowthTrigger084A = 0x84A,         /* Read out of the retail placement data: moonpass/MSBush growthTriggerGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSVinePlanted084B = 0x84B,               /* Read out of the retail placement data: moonpass/MSVine plantedGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSVineGrowthTrigger084C = 0x84C,         /* Read out of the retail placement data: moonpass/MSVine growthTriggerGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSBushPlanted084D = 0x84D,               /* Read out of the retail placement data: moonpass/MSBush plantedGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSBushGrowthTrigger084E = 0x84E,         /* Read out of the retail placement data: moonpass/MSBush growthTriggerGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSVinePlanted0850 = 0x850,               /* Read out of the retail placement data: moonpass/MSVine plantedGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSVineGrowthTrigger0851 = 0x851,         /* Read out of the retail placement data: moonpass/MSVine growthTriggerGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSBushPlanted0852 = 0x852,               /* Read out of the retail placement data: moonpass/MSBush plantedGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSBushGrowthTrigger0853 = 0x853,         /* Read out of the retail placement data: moonpass/MSBush growthTriggerGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSVinePlanted0854 = 0x854,               /* Read out of the retail placement data: moonpass/MSVine plantedGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSVineGrowthTrigger0855 = 0x855,         /* Read out of the retail placement data: moonpass/MSVine growthTriggerGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MoonSeedSpot1Harvested = 0x856,              /* One of the eleven moon-seed planting spots MSPlantingS maps from its placement ident: spot 1, ident 0x41A5B, which Rena places in moonpass. This is its harvested bit, raised once the grown plant is cut and taken */
    GAMEBIT_ITEM_MoonSeed_Used = 0x857,                  /* table 2; hint 309; ref moonpass/HitAnimator target */
    GAMEBIT_MoonSeedSpot2Harvested = 0x858,              /* One of the eleven moon-seed planting spots MSPlantingS maps from its placement ident: spot 2, ident 0x41A59, which Rena places in moonpass. This is its harvested bit, raised once the grown plant is cut and taken */
    GAMEBIT_MMP_SeqBit180859 = 0x859,                    /* Named from map data alone - nothing in the code or in any name list mentions it: moonpass/MMP_seqobje objId= param=bit18; moonpass/HitAnimator objId= param=target; table 2 */
    GAMEBIT_MoonSeedSpot3Harvested = 0x85A,              /* One of the eleven moon-seed planting spots MSPlantingS maps from its placement ident: spot 3, ident 0x41A5C, which Rena places in moonpass. This is its harvested bit, raised once the grown plant is cut and taken */
    GAMEBIT_MMP_SeqBit18085B = 0x85B,                    /* Named from map data alone - nothing in the code or in any name list mentions it: moonpass/MMP_seqobje objId= param=bit18; moonpass/HitAnimator objId= param=target; table 2 */
    GAMEBIT_DIM2_CannonRelated085E = 0x85E,              /* table 2; ref snowmines2/HitAnimator target */
    GAMEBIT_MMP_MSBushPlanted0860 = 0x860,               /* Read out of the retail placement data: moonpass/MSBush plantedGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSBushGrowthTrigger0861 = 0x861,         /* Read out of the retail placement data: moonpass/MSBush growthTriggerGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSVinePlanted0862 = 0x862,               /* Read out of the retail placement data: moonpass/MSVine plantedGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSVineGrowthTrigger0863 = 0x863,         /* Read out of the retail placement data: moonpass/MSVine growthTriggerGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MoonSeedSpot4Harvested = 0x864,              /* One of the eleven moon-seed planting spots MSPlantingS maps from its placement ident: spot 4, ident 0x41A5D, which Rena places in moonpass. This is its harvested bit, raised once the grown plant is cut and taken */
    GAMEBIT_MMP_SeqBit180865 = 0x865,                    /* Named from map data alone - nothing in the code or in any name list mentions it: moonpass/MMP_seqobje objId= param=bit18; moonpass/HitAnimator objId= param=target; table 2 */
    GAMEBIT_MoonSeedSpot1Planted = 0x866,                /* One of the eleven moon-seed planting spots MSPlantingS maps from its placement ident: spot 1, ident 0x41A5B, which Rena places in moonpass. This is its planted bit; planting also decrements the shared GAMEBIT_ITEM_MoonSeed_Count */
    GAMEBIT_MoonSeedSpot2Planted = 0x867,                /* One of the eleven moon-seed planting spots MSPlantingS maps from its placement ident: spot 2, ident 0x41A59, which Rena places in moonpass. This is its planted bit; planting also decrements the shared GAMEBIT_ITEM_MoonSeed_Count */
    GAMEBIT_MoonSeedSpot3Planted = 0x868,                /* One of the eleven moon-seed planting spots MSPlantingS maps from its placement ident: spot 3, ident 0x41A5C, which Rena places in moonpass. This is its planted bit; planting also decrements the shared GAMEBIT_ITEM_MoonSeed_Count */
    GAMEBIT_MoonSeedSpot4Planted = 0x869,                /* One of the eleven moon-seed planting spots MSPlantingS maps from its placement ident: spot 4, ident 0x41A5D, which Rena places in moonpass. This is its planted bit; planting also decrements the shared GAMEBIT_ITEM_MoonSeed_Count */
    GAMEBIT_ITEM_MoonSeed_Count = 0x86A,                 /* table 2; size 3. MSPlantingS names it GAMEBIT_MOONSEED_COUNT, agreeing it is a count. Backs the collectable item C-menu entry the game labels "Plant MoonSeed" (its owned bit) */
    GAMEBIT_DBEggPickedUp086D = 0x86D,                   /* Raised beside GAMEBIT_DBEggCarried at both pickup points, with nothing in the code reading it back */
    GAMEBIT_DIM2_CannonRelated0874 = 0x874,              /* table 2; ref snowmines2/HitAnimator target */
    GAMEBIT_MMPAsteroidRelated087B = 0x87B,              /* table 2; size 2 */
    GAMEBIT_SH_WarpStoneRelated0884 = 0x884,             /* table 2 */
    GAMEBIT_ITEM_RockCandyRelated0886 = 0x886,           /* table 2; related to rock candy */
    GAMEBIT_SH_SawWarpStoneIntro = 0x887,                /* table 2 */
    GAMEBIT_MMP_TrenchFEnable088A = 0x88A,               /* Read out of the retail placement data: moonpass/MMP_trenchF enableGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_AsteroidRelated088B = 0x88B,             /* Cleared by the Moon Mountain Pass asteroid once its own clear-timer runs out, with nothing in the code setting it */
    GAMEBIT_MMP_MoonRockPedestalCount = 0x88C,           /* How many moon rocks are on their pedestals - a count, not a flag. MMP_moonroc reads it beside GAMEBIT_MMP_MoonRockInventoryCount, and the Moon Mountain Pass asteroid reads that same count straight into its own intensity, except while GAMEBIT_MMP_AsteroidForceIntensity pins it to 1 */
    GAMEBIT_MMP_GyserveDisable088E = 0x88E,              /* Read out of the retail placement data: moonpass/MMP_gyserve disableGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_GyserveDisable088F = 0x88F,              /* Read out of the retail placement data: moonpass/MMP_gyserve disableGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_GyserveDisable0890 = 0x890,              /* Read out of the retail placement data: moonpass/MMP_gyserve disableGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_GyserveDisable0891 = 0x891,              /* Read out of the retail placement data: moonpass/MMP_gyserve disableGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_GyserveDisable0892 = 0x892,              /* Read out of the retail placement data: moonpass/MMP_gyserve disableGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_GyserveDisable0893 = 0x893,              /* Read out of the retail placement data: moonpass/MMP_gyserve disableGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MoonRockInventoryCount = 0x894,          /* The DLL names this one itself: MMP_MOON_ROCK_INVENTORY_COUNT_GAMEBIT in MMP_moonroc.c */
    GAMEBIT_MMP_MoonrocKind0895 = 0x895,                 /* Read out of the retail placement data: moonpass/MMP_moonroc kindGameBit x1; 1 placement; BITTABLE gives it a width of 3 bits, so it is a field rather than a flag. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MoonrocKind0896 = 0x896,                 /* Read out of the retail placement data: moonpass/MMP_moonroc kindGameBit x1; 1 placement; BITTABLE gives it a width of 3 bits, so it is a field rather than a flag. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MoonrocKind0897 = 0x897,                 /* Read out of the retail placement data: moonpass/MMP_moonroc kindGameBit x1; 1 placement; BITTABLE gives it a width of 3 bits, so it is a field rather than a flag. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_WM_SeqStarted0899 = 0x899,                   /* Named from map data alone - nothing in the code or in any name list mentions it: warlock/WM_seqpoint objId= param=seqStarted; table 2 */
    GAMEBIT_MMP_MovedMeteor = 0x89B,                     /* table 2; hint 310; ref moonpass/HitAnimator target */
    GAMEBIT_DIM_LevelControl089D = 0x89D,                /* The DLL names this one itself: DIM_LEVEL_CONTROL_GAMEBIT_089D in DIM_LevelCo.c */
    GAMEBIT_DIMLogFireDouse089F = 0x89F,                 /* Read out of the retail placement data: snowmines4/DIMLogFire douseGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_ITEM_Spirit3_Released = 0x8A0,               /* table 2; hint 357: "Released Third Krazoa Spirit". Backs the collectable item C-menu entry the game labels "Unknown" (its owned bit) */
    GAMEBIT_WM_Warp1Enabled = 0x8A1,                     /* table 2; ref warlock/Transporter enabled */
    GAMEBIT_WM_SpiritPlace3Ready = 0x8A2,                /* table 2; gates spirit-place 3 and its return pad. Backs the collectable item C-menu entry the game labels "Unknown" (its used bit) */
    GAMEBIT_VFP_Param2008A3 = 0x8A3,                     /* Named from map data alone - nothing in the code or in any name list mentions it: temple/VFP_seqpoin objId= param=_20; table 2 */
    GAMEBIT_DIM_LevelControl08A4 = 0x8A4,                /* The DLL names this one itself: DIM_LEVEL_CONTROL_GAMEBIT_08A4 in DIM_LevelCo.c */
    GAMEBIT_DIM_LevelControl08A5 = 0x8A5,                /* The DLL names this one itself: DIM_LEVEL_CONTROL_GAMEBIT_08A5 in DIM_LevelCo.c */
    GAMEBIT_SH_SfxPlayerBit08A8 = 0x8A8,                 /* Read out of the retail placement data: hollow/sfxPlayer gameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_VFP_Param2008B6 = 0x8B6,                     /* Named from map data alone - nothing in the code or in any name list mentions it: temple/VFP_seqpoin objId= param=_20; table 2 */
    GAMEBIT_VFP_Param2008B7 = 0x8B7,                     /* Named from map data alone - nothing in the code or in any name list mentions it: temple/VFP_seqpoin objId= param=_20; table 2 */
    GAMEBIT_CF_Item8B8 = 0x8B8,                          /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_Item8B9 = 0x8B9,                          /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_Item8BA = 0x8BA,                          /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_HitAnimTarget08BF = 0x8BF,                /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/HitAnimator objId= param=target; fortress/CFseqobject objId= param=bit1A; fortress/StaffLeverO objId= param=activated; table 2 */
    GAMEBIT_CF_FallLadderBase08C0 = 0x8C0,               /* Read out of the retail placement data: fortress/Fall_Ladder baseGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_TREX_LevelName8C5 = 0x8C5,                   /* Rena's U0 dataset; table 0 */
    GAMEBIT_CF_LeverActivated08C8 = 0x8C8,               /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/StaffLeverT objId= param=activated; table 2 */
    GAMEBIT_CF_HitAnimTarget08C9 = 0x8C9,                /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/HitAnimator objId= param=target; fortress/ExplodePlan objId= param=exploded; fortress/ExplodePlan objId= param=collected; table 2 */
    GAMEBIT_CF_OnExplode08CA = 0x8CA,                    /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/ExplodePlan objId= param=onExplode; table 2 */
    GAMEBIT_CF_SeqBit1A08CD = 0x8CD,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFseqobject objId= param=bit1A; table 1 */
    GAMEBIT_CF_SeqBit1808CE = 0x8CE,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFseqobject objId= param=bit18; table 1 */
    GAMEBIT_CF_GuardianLanded = 0x8E9,                   /* The DLL names this one itself: GAMEBIT_CFGUARDIAN_LANDED in CFGuardian.c */
    GAMEBIT_KP_ActNo = 0x8EC,                            /* table 1; size 4; old "krazoapalace" map */
    GAMEBIT_KP_ObjGroups = 0x8ED,                        /* table 3; size 32 */
    GAMEBIT_OFB_DFPseqpoinDisable08EE = 0x8EE,           /* A DFP sequence point's disable bit, from its placement's field at 0x20. Two of the ids that slot holds - 0xCB1 and 0xEE0 - were already named from other evidence, which is what vindicates the slot; DfpSeqPointPlacement overruns the 0x24 record at its tail, but this field is inside it */
    GAMEBIT_WM_Seq8F4 = 0x8F4,                           /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_CurveRequired08F5 = 0x8F5,               /* A curve-node gate read from the retail romlist: temple requiredBit x2. RomCurveDef puts requiredBit at 0x30 and forbiddenBit at 0x32, and the path search only walks a node when its required bit is set and its forbidden bit is clear. Only curve variants whose layout is corroborated were read - the 0x34/type-36 nodes are 88% ids already named from other evidence with nothing out of range, whereas the 0x44/type-38 variant is 63% out of range there and was left alone */
    GAMEBIT_CF_Open08FC = 0x8FC,                         /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/SH_Portcull objId= param=open; table 2 */
    GAMEBIT_CF_SHPortcullOpen08FD = 0x8FD,               /* Read out of the retail placement data: fortress/SH_Portcull open x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_BabyCloudRunnerCaptureCount = 0x901,         /* The DLL names this one itself: BABYCLOUDRUNNER_CAPTURE_COUNT_GAME_BIT in 332.c */
    GAMEBIT_ITEM_WaterSpellStone1_902 = 0x902,           /* table 1 */
    GAMEBIT_WM_SwitchCamActive = 0x905,                  /* table 2; camera pointing at door opened by pressure switch */
    GAMEBIT_CF_SeqBit180909 = 0x909,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFseqobject objId= param=bit18; table 1 */
    GAMEBIT_SC_LVBlock2Related090B = 0x90B,              /* One of the three bits sc_levelcontrol raises the moment GAMEBIT_ITEM_LVBlock2_Used is set */
    GAMEBIT_SC_SteppingClosedLatch090C = 0x90C,          /* Read out of the retail placement data: swapcircle/SC_stepping closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SawMagic = 0x90D,                            /* table 2; Have collected a Staff Energy Gem (if 0, explain it when you collect one). CAUTION: DLL 255 names the same bit its magic-gem claimed latch, describing it as a per-frame single-pickup latch rather than anything the player saw */
    GAMEBIT_SawBigHealth = 0x90E,                        /* table 2 */
    GAMEBIT_SawApple = 0x90F,                            /* table 2; small health pickup */
    GAMEBIT_SawScarab = 0x910,                           /* table 2 */
    GAMEBIT_SawWarpPad = 0x912,                          /* table 2; if not, explains what it is when touching one */
    GAMEBIT_PushableRelated0913 = 0x913,                 /* table 2 */
    GAMEBIT_ITEM_50ScarabBag_Got = 0x919,                /* table 2 */
    GAMEBIT_ITEM_100ScarabBag_Got = 0x91A,               /* table 2 */
    GAMEBIT_ITEM_200ScarabBag_Got = 0x91B,               /* table 2 */
    GAMEBIT_ITEM_WMGoldKey_Got = 0x91C,                  /* table 1; opens door to barrel at start as Krystal; collecting this also enables C menu. Backs the collectable item C-menu entry the game labels "Use Gold Key" (its owned bit) */
    GAMEBIT_MC_IsExiting = 0x91E,                        /* table 0; set to respawn from cave entrance */
    GAMEBIT_CF_HitAnimTarget0920 = 0x920,                /* Named from map data alone - nothing in the code or in any name list mentions it: clouddungeon/HitAnimator objId= param=target; table 1 */
    GAMEBIT_LearnedToSpeak = 0x92A,                      /* table 2; Told how to speak to NPCs */
    GAMEBIT_SC_Open092E = 0x92E,                         /* Named from map data alone - nothing in the code or in any name list mentions it: swapcircle/SC_capeclaw objId= param=open; swapcircle/HitAnimator objId= param=target; table 2 */
    GAMEBIT_SC_CapeclawClosedLatch092F = 0x92F,          /* Read out of the retail placement data: swapcircle/SC_capeclaw closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SawCMenuExplanation = 0x930,                 /* table 2 */
    GAMEBIT_CC_Seq931 = 0x931,                           /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_KytesMumRelated0933 = 0x933,              /* table 1; cleared as Kyte's mum enters either of her quest modes, beside GAMEBIT_CF_KytesMumRelated0934 */
    GAMEBIT_CF_KytesMumRelated0934 = 0x934,              /* table 1; cleared as Kyte's mum enters either of her quest modes */
    GAMEBIT_CF_PickKrystHide0938 = 0x938,                /* Read out of the retail placement data: clouddungeon/CFPickKryst hideGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CF_EscapedDungeon = 0x939,                   /* table 2; hint 327; Exploded dungeon ceiling to be able to get disguise */
    GAMEBIT_CF_WinPrisonClosedLatch093A = 0x93A,         /* Read out of the retail placement data: clouddungeon/CFWinPrison closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CF_Activate093F = 0x93F,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/TrigPln objId= param=activate; table 1 */
    GAMEBIT_CF_RescuedBabies = 0x940,                    /* table 2; hint 330 */
    GAMEBIT_CF_BabyRelated941 = 0x941,                   /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_WallExploded094A = 0x94A,                 /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFbrokenWal objId= param=exploded; fortress/HitAnimator objId= param=target; table 2 */
    GAMEBIT_CF_OnExplode094B = 0x94B,                    /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFbrokenWal objId= param=onExplode; table 2 */
    GAMEBIT_CF_HaveStaff = 0x94E,                        /* table 2 */
    GAMEBIT_CF_NotRecoveredStaff = 0x94F,                /* table 2 */
    GAMEBIT_ITEM_Flute_Got = 0x953,                      /* table 2. Backs the collectable item C-menu entry the game labels "Blow Flute" (its owned bit) */
    GAMEBIT_CF_SeqBit180954 = 0x954,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFseqobject objId= param=bit18; table 1 */
    GAMEBIT_CF_SeqBit1A0955 = 0x955,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFseqobject objId= param=bit1A; table 1 */
    GAMEBIT_FlewToPlanet = 0x956,                        /* table 2; hint 253; ref hollow/Landed_Arwi Visible */
    GAMEBIT_ITEM_StaffBooster_Got = 0x957,               /* table 2; hint 272; ref hollow2/MagicCaveTo Collected. Backs the staff ability C-menu entry the game labels "Staff Booster" (its owned bit) */
    GAMEBIT_ITEM_LaserSpell_Got = 0x958,                 /* table 2; Have Rapid Fire Laser Spell (unused) */
    GAMEBIT_CF_ArwingVisible = 0x959,                    /* Rena's U0 dataset; table 1 */
    GAMEBIT_ITEM_PortalSpell_Disabled = 0x960,           /* table 2. Backs the staff ability C-menu entry the game labels "Open Portal" (its active bit) */
    GAMEBIT_ITEM_Spell0961_Disabled = 0x961,             /* table 2; set when Krystal loses staff, cleared when Fox finds it. Backs the staff ability C-menu entry the game labels "Freeze Blast" (its active bit) */
    GAMEBIT_ITEM_StaffBooster_Disabled = 0x964,          /* table 2. Backs the staff ability C-menu entry the game labels "Staff Booster" (its active bit) */
    GAMEBIT_ITEM_Spell0965_Disabled = 0x965,             /* table 2; set when Krystal loses staff, cleared when Fox finds it */
    GAMEBIT_ITEM_DinoHorn_Disabled = 0x966,              /* table 3. Backs the collectable item C-menu entry the game labels "Blow Horn" (its active bit) */
    GAMEBIT_ITEM_Firefly_Disabled = 0x967,               /* table 2; disables lantern in menu. Backs the collectable item C-menu entry the game labels "Use Lantern" (its active bit) */
    GAMEBIT_Tricky_CantFeed = 0x968,                     /* table 3. Backs the collectable item C-menu entry the game labels "Feed to Tricky" (its active bit) */
    GAMEBIT_ITEM_SharpClawDisguise_Disabled = 0x969,     /* table 2. Backs the staff ability C-menu entry the game labels "SharpClaw Disguise" (its active bit) */
    GAMEBIT_ITEM_SuperQuake_Disabled = 0x96B,            /* table 2. Backs the staff ability C-menu entry the game labels "Ground Quake" (its active bit); and the staff ability C-menu entry the game labels "Super Quake" (its active bit) */
    GAMEBIT_MMSH_Pressed096D = 0x96D,                    /* Named from map data alone - nothing in the code or in any name list mentions it: mmshrine/ECSH_Pressu objId= param=pressed; mmshrine/SC_Shrine_d objId= param=open; table 0 */
    GAMEBIT_MMSH_Pressed096E = 0x96E,                    /* Named from map data alone - nothing in the code or in any name list mentions it: mmshrine/ECSH_Pressu objId= param=pressed; mmshrine/SC_Shrine_d objId= param=open; table 0 */
    GAMEBIT_MMSH_Pressed096F = 0x96F,                    /* Named from map data alone - nothing in the code or in any name list mentions it: mmshrine/ECSH_Pressu objId= param=pressed; mmshrine/SC_Shrine_d objId= param=open; table 0 */
    GAMEBIT_CF_DoStandUpAnim = 0x970,                    /* table 1; triggers a falling and getting back up scene on map reload */
    GAMEBIT_CF_Activate0972 = 0x972,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/TrigPln objId= param=activate; table 1 */
    GAMEBIT_CFPowerBaseRelated0973 = 0x973,              /* cleared when a power gem is installed in a CloudRunner Fortress power base */
    GAMEBIT_CFLever0974 = 0x974,                         /* table 2; ref fortress/StaffLeverO activated */
    GAMEBIT_CFLever0975 = 0x975,                         /* table 2; ref fortress/StaffLeverO activated */
    GAMEBIT_CF_SeqBit180976 = 0x976,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CAMERAseqob objId= param=bit18; table 2 */
    GAMEBIT_CF_SeqBit180977 = 0x977,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CAMERAseqob objId= param=bit18; table 2 */
    GAMEBIT_CF_Activate0979 = 0x979,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/TrigPln objId= param=activate; table 1 */
    GAMEBIT_CloudRaceResetBit0983 = 0x983,               /* One of the bits CRCloudRace clears as it resets the CloudRunner race; Rena's U0 dataset spells it CFRelated0983, which carries no reading of its own */
    GAMEBIT_CloudRaceResetBit0984 = 0x984,               /* One of the bits CRCloudRace clears as it resets the CloudRunner race; Rena's U0 dataset spells it CFRelated0984, which carries no reading of its own */
    GAMEBIT_ITEM_FireBlaster_Disabled = 0x986,           /* table 2. Backs the staff ability C-menu entry the game labels "Fire Blaster" (its active bit) */
    GAMEBIT_MMP_MSBushPlanted098A = 0x98A,               /* Read out of the retail placement data: moonpass/MSBush plantedGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSBushGrowthTrigger098B = 0x98B,         /* Read out of the retail placement data: moonpass/MSBush growthTriggerGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSVinePlanted098C = 0x98C,               /* Read out of the retail placement data: moonpass/MSVine plantedGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSVineGrowthTrigger098D = 0x98D,         /* Read out of the retail placement data: moonpass/MSVine growthTriggerGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSBushPlanted098E = 0x98E,               /* Read out of the retail placement data: moonpass/MSBush plantedGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSBushGrowthTrigger098F = 0x98F,         /* Read out of the retail placement data: moonpass/MSBush growthTriggerGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSVinePlanted0990 = 0x990,               /* Read out of the retail placement data: moonpass/MSVine plantedGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSVineGrowthTrigger0991 = 0x991,         /* Read out of the retail placement data: moonpass/MSVine growthTriggerGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSBushPlanted0992 = 0x992,               /* Read out of the retail placement data: moonpass/MSBush plantedGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSBushGrowthTrigger0993 = 0x993,         /* Read out of the retail placement data: moonpass/MSBush growthTriggerGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSVinePlanted0994 = 0x994,               /* Read out of the retail placement data: moonpass/MSVine plantedGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSVineGrowthTrigger0995 = 0x995,         /* Read out of the retail placement data: moonpass/MSVine growthTriggerGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSBushPlanted0996 = 0x996,               /* Read out of the retail placement data: moonpass/MSBush plantedGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSBushGrowthTrigger0997 = 0x997,         /* Read out of the retail placement data: moonpass/MSBush growthTriggerGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSVinePlanted0998 = 0x998,               /* Read out of the retail placement data: moonpass/MSVine plantedGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_MSVineGrowthTrigger0999 = 0x999,         /* Read out of the retail placement data: moonpass/MSVine growthTriggerGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MoonSeedSpot5Harvested = 0x99A,              /* One of the eleven moon-seed planting spots MSPlantingS maps from its placement ident: spot 5, ident 0x43E04, which Rena places in moonpass. This is its harvested bit, raised once the grown plant is cut and taken */
    GAMEBIT_MMP_SeqBit18099B = 0x99B,                    /* Named from map data alone - nothing in the code or in any name list mentions it: moonpass/MMP_seqobje objId= param=bit18; moonpass/HitAnimator objId= param=target; table 2 */
    GAMEBIT_MoonSeedSpot6Harvested = 0x99C,              /* One of the eleven moon-seed planting spots MSPlantingS maps from its placement ident: spot 6, ident 0x43E1F, which Rena places in moonpass. This is its harvested bit, raised once the grown plant is cut and taken */
    GAMEBIT_MMP_HitAnimTarget099D = 0x99D,               /* Named from map data alone - nothing in the code or in any name list mentions it: moonpass/HitAnimator objId= param=target; moonpass/MMP_seqobje objId= param=bit18; table 2 */
    GAMEBIT_MoonSeedSpot7Harvested = 0x99E,              /* One of the eleven moon-seed planting spots MSPlantingS maps from its placement ident: spot 7, ident 0x43E20, which Rena places in moonpass. This is its harvested bit, raised once the grown plant is cut and taken */
    GAMEBIT_MMP_HitAnimTarget099F = 0x99F,               /* Named from map data alone - nothing in the code or in any name list mentions it: moonpass/HitAnimator objId= param=target; moonpass/MMP_seqobje objId= param=bit18; table 2 */
    GAMEBIT_MoonSeedSpot8Harvested = 0x9A0,              /* One of the eleven moon-seed planting spots MSPlantingS maps from its placement ident: spot 8, ident 0x43E21, which Rena places in moonpass. This is its harvested bit, raised once the grown plant is cut and taken */
    GAMEBIT_MMP_HitAnimTarget09A1 = 0x9A1,               /* Named from map data alone - nothing in the code or in any name list mentions it: moonpass/HitAnimator objId= param=target; moonpass/MMP_seqobje objId= param=bit18; table 2 */
    GAMEBIT_MoonSeedSpot5Planted = 0x9A2,                /* One of the eleven moon-seed planting spots MSPlantingS maps from its placement ident: spot 5, ident 0x43E04, which Rena places in moonpass. This is its planted bit; planting also decrements the shared GAMEBIT_ITEM_MoonSeed_Count */
    GAMEBIT_MoonSeedSpot6Planted = 0x9A3,                /* One of the eleven moon-seed planting spots MSPlantingS maps from its placement ident: spot 6, ident 0x43E1F, which Rena places in moonpass. This is its planted bit; planting also decrements the shared GAMEBIT_ITEM_MoonSeed_Count */
    GAMEBIT_MoonSeedSpot7Planted = 0x9A4,                /* One of the eleven moon-seed planting spots MSPlantingS maps from its placement ident: spot 7, ident 0x43E20, which Rena places in moonpass. This is its planted bit; planting also decrements the shared GAMEBIT_ITEM_MoonSeed_Count */
    GAMEBIT_MoonSeedSpot8Planted = 0x9A5,                /* One of the eleven moon-seed planting spots MSPlantingS maps from its placement ident: spot 8, ident 0x43E21, which Rena places in moonpass. This is its planted bit; planting also decrements the shared GAMEBIT_ITEM_MoonSeed_Count */
    GAMEBIT_FoxSawKrazoa = 0x9A6,                        /* table 2; hint 307 */
    GAMEBIT_MMP_SeqBit1A09A7 = 0x9A7,                    /* Named from map data alone - nothing in the code or in any name list mentions it: moonpass/MMP_seqobje objId= param=bit1A; table 0 */
    GAMEBIT_CollectedFlag09A8 = 0x9A8,                   /* table 2; did collect something (moon seed?) */
    GAMEBIT_CF_SeqBit1809A9 = 0x9A9,                     /* Named from map data alone - nothing in the code or in any name list mentions it: cloudrace/CFRaceSeqob objId= param=bit18; table 1 */
    GAMEBIT_WM_KrystalLanded = 0x9AA,                    /* table 2; hint 246; Krystal encountered General Scales */
    GAMEBIT_WM_KrystalTalkedToDinoAfterTest1 = 0x9AB,    /* table 2 */
    GAMEBIT_MMP_MoonRockPlacementEvent = 0x9AE,          /* The DLL names this one itself: MMP_MOON_ROCK_PLACEMENT_EVENT_GAMEBIT in MMP_moonroc.c */
    GAMEBIT_MMP_SeqBit1809AF = 0x9AF,                    /* Named from map data alone - nothing in the code or in any name list mentions it: moonpass/MMP_seqobje objId= param=bit18; table 2 */
    GAMEBIT_VFP_PodiumPrereq09B1 = 0x9B1,                /* One of the two bits VFP_LevelCo waits on before it raises GAMEBIT_VFP_PodiumsActivated */
    GAMEBIT_VFP_PodiumPrereq09B2 = 0x9B2,                /* The other bit GAMEBIT_VFP_PodiumsActivated waits on */
    GAMEBIT_VFP_LiftgraGameBitB09B3 = 0x9B3,             /* Read out of the retail placement data: temple/VFP_liftgra gameBitB x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DR_GeneratorArmed09B9 = 0x9B9,               /* The Dragon Rock generator latches its own armed flag the first update it sees this set */
    GAMEBIT_VFP_Param1E09BA = 0x9BA,                     /* Named from map data alone - nothing in the code or in any name list mentions it: temple/VFP_seqpoin objId= param=_1E; table 2 */
    GAMEBIT_VFP_HitAnimTarget09BC = 0x9BC,               /* Named from map data alone - nothing in the code or in any name list mentions it: temple/HitAnimator objId= param=target; temple/VFP_flamepo objId= param=activated; temple/CAMERAseqob objId= param=bit1A; table 2 */
    GAMEBIT_DR_CFWindLiftActivation09C0 = 0x9C0,         /* Read out of the retail placement data: dragrock/CFWindLift activationGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DR_CFWindLiftActivation09C1 = 0x9C1,         /* Read out of the retail placement data: dragrock/CFWindLift activationGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DR_CFWindLiftActivation09C2 = 0x9C2,         /* Read out of the retail placement data: dragrock/CFWindLift activationGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DR_HighTopSwitch1 = 0x9C7,                   /* table 1 */
    GAMEBIT_DR_HighTopSwitch2 = 0x9C9,                   /* table 1 */
    GAMEBIT_DR_HighTopSwitch3 = 0x9CB,                   /* table 1 */
    GAMEBIT_DR_HighTopSwitch4 = 0x9CD,                   /* table 1 */
    GAMEBIT_IncomingCommunication = 0x9D5,               /* table 0; Slippy calling you */
    GAMEBIT_ArwingRelated09D6 = 0x9D6,                   /* table 1 */
    GAMEBIT_ARW_SeqBit1809D9 = 0x9D9,                    /* Named from map data alone - nothing in the code or in any name list mentions it: arwingcity/ARWSeqObjec objId= param=bit18; arwingcloud/ARWSeqObjec objId= param=bit18; arwingdarkice/ARWSeqObjec objId= param=bit18 (+2 more); table 1 */
    GAMEBIT_ARW_SeqBit1809DA = 0x9DA,                    /* Named from map data alone - nothing in the code or in any name list mentions it: arwingcity/ARWSeqObjec objId= param=bit18; arwingcloud/ARWSeqObjec objId= param=bit18; arwingdarkice/ARWSeqObjec objId= param=bit18 (+2 more); table 1 */
    GAMEBIT_DR_TowerSwitch1 = 0x9E0,                     /* First of the four dragrock DR_TowerSwi switches (objIds 0x49B1B/0x49B1C/0x49B16/0x49B18, param 0x1E); while any of the four is still clear drmusiccont restarts a stinger timer on every change and stings when it runs out */
    GAMEBIT_DR_TowerSwitch2 = 0x9E1,                     /* Second Dragon Rock tower switch */
    GAMEBIT_DR_TowerSwitch3 = 0x9E2,                     /* Third Dragon Rock tower switch */
    GAMEBIT_DR_Param2009E3 = 0x9E3,                      /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/DR_TowerSwi objId= param=_20; table 0 */
    GAMEBIT_DR_Param2009E4 = 0x9E4,                      /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/DR_TowerSwi objId= param=_20; table 0 */
    GAMEBIT_DR_Param2009E5 = 0x9E5,                      /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/DR_TowerSwi objId= param=_20; table 0 */
    GAMEBIT_DR_Param2009E6 = 0x9E6,                      /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/DR_TowerSwi objId= param=_20; table 0 */
    GAMEBIT_DR_TowerSwitch4 = 0x9E7,                     /* Fourth Dragon Rock tower switch */
    GAMEBIT_DR_CreatorSpawn09E8 = 0x9E8,                 /* Read out of the retail placement data: dragrock/DR_Creator spawnGameBit x2; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DR_FlewTo = 0x9E9,                           /* table 2; hint 385; cleared when Arwing flies to Dragon Rock */
    GAMEBIT_DR_EarthWarriorUnknown_1 = 0x9EC,            /* read by DR_EarthWar.c  */
    GAMEBIT_DIM_BitIncOnDeath09ED = 0x9ED,               /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/sharpclawSn objId= param=bit_incOnDeath; table 2 */
    GAMEBIT_DIM_HitAnimTarget09EF = 0x9EF,               /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/HitAnimator objId= param=target; table 2 */
    GAMEBIT_DR_HighTopRestartArmed = 0x9F0,              /* table 3; drmusiccont is its only reader - while it is set and GAMEBIT_DR_RescuedHighTop is still clear the DLL installs a fixed restart point, and clears that restart point the moment either condition lapses */
    GAMEBIT_DR_SeqBit1A09F2 = 0x9F2,                     /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/DR_Seqobj objId= param=bit1A; dragrock/TrigBits objId= param=activate; table 1 */
    GAMEBIT_DR_EnteredDrakorTower = 0x9F3,               /* table 2; hint 394 */
    GAMEBIT_DFP_Statue1VariantD = 0x9F5,                 /* The DLL names this one itself: GAMEBIT_DFP_STATUE1_VARIANT_D in DFP_Statue1.c */
    GAMEBIT_DIM_RodeSnowHornThroughGates = 0x9F6,        /* table 2; hint 285; ref snowmines/HitAnimator target */
    GAMEBIT_DFP_RotatepSingleComplete = 0x9F7,           /* The DLL names this one itself: DFP_ROTATEP_GAMEBIT_SINGLE_COMPLETE in DFP_RotateP.c */
    GAMEBIT_DRBOT_LeverActivated09FB = 0x9FB,            /* Named from map data alone - nothing in the code or in any name list mentions it: dragbot/StaffLeverO objId= param=activated; table 0 */
    GAMEBIT_VFP_SeqBit1A09FD = 0x9FD,                    /* Named from map data alone - nothing in the code or in any name list mentions it: temple/VFPSeqObj objId= param=bit1A; table 2 */
    GAMEBIT_VFP_SeqBit180A00 = 0xA00,                    /* Named from map data alone - nothing in the code or in any name list mentions it: temple/CAMERAseqob objId= param=bit18; table 2 */
    GAMEBIT_DRBOT_LeverActivated0A01 = 0xA01,            /* Named from map data alone - nothing in the code or in any name list mentions it: dragbot/StaffLeverO objId= param=activated; table 0 */
    GAMEBIT_DRBOT_SeqBit1A0A03 = 0xA03,                  /* Named from map data alone - nothing in the code or in any name list mentions it: dragbot/DR_SeqobjBo objId= param=bit1A; table 1 */
    GAMEBIT_DRBOT_SeqBit1A0A04 = 0xA04,                  /* Named from map data alone - nothing in the code or in any name list mentions it: dragbot/DR_SeqobjBo objId= param=bit1A; table 1 */
    GAMEBIT_DRBOT_SeqBit1A0A05 = 0xA05,                  /* Named from map data alone - nothing in the code or in any name list mentions it: dragbot/DR_SeqobjBo objId= param=bit1A; table 1 */
    GAMEBIT_DRBOT_OnExplode0A07 = 0xA07,                 /* Named from map data alone - nothing in the code or in any name list mentions it: dragbot/ExplodeWall objId= param=onExplode; table 1 */
    GAMEBIT_VFP_SCsettelmeClosedLatch0A09 = 0xA09,       /* Read out of the retail placement data: temple/SC_settelme closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_VFP_StatuebActivation0A0A = 0xA0A,           /* Read out of the retail placement data: temple/VFP_statueb activationGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_VFP_StatuebActivation0A0B = 0xA0B,           /* Read out of the retail placement data: temple/VFP_statueb activationGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_VFP_StatuebActivation0A0C = 0xA0C,           /* Read out of the retail placement data: temple/VFP_statueb activationGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_PushableRelated0A1A = 0xA1A,                 /* table 0 */
    GAMEBIT_DIM_TrickyTrigger = 0xA1B,                   /* The DLL names this one itself: DIMTRICKY_TRIGGER_GAMEBIT in DIM_tricky.c */
    GAMEBIT_DRBOT_SeqBit180A1C = 0xA1C,                  /* Named from map data alone - nothing in the code or in any name list mentions it: dragbot/DR_SeqobjBo objId= param=bit18; table 1 */
    GAMEBIT_DRBOT_SeqBit1A0A1D = 0xA1D,                  /* Named from map data alone - nothing in the code or in any name list mentions it: dragbot/DR_SeqobjBo objId= param=bit1A; dragbot/DR_SeqobjBo objId= param=bit18; table 1 */
    GAMEBIT_DIM_CannonRelated0A21 = 0xA21,               /* table 2; related to DIM cannon */
    GAMEBIT_DIM_TruthHorVisibility0A23 = 0xA23,          /* Read out of the retail placement data: snowmines/DIMTruthHor visibilityGameBit x1; snowmines/DIMTruthHor gameBit x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SH_TrickyGuardTrickyInRange0A29 = 0xA29,     /* Read out of the retail placement data: hollow/TrickyGuard trickyInRangeGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SH_TrickyGuardTrickyInRange0A2A = 0xA2A,     /* Read out of the retail placement data: hollow/TrickyGuard trickyInRangeGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SH_TrickyGuardTrickyInRange0A2B = 0xA2B,     /* Read out of the retail placement data: hollow/TrickyGuard trickyInRangeGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SH_TrickyGuardTrickyInRange0A2C = 0xA2C,     /* Read out of the retail placement data: hollow/TrickyGuard trickyInRangeGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SH_Enabled0A2D = 0xA2D,                      /* Named from map data alone - nothing in the code or in any name list mentions it: hollow/CNTcounter objId= param=enabled; table 0 */
    GAMEBIT_SH_Target0A2F = 0xA2F,                       /* Named from map data alone - nothing in the code or in any name list mentions it: hollow/CNTcounter objId= param=target; hollow/SH_newseqob objId= param=needBit; table 0 */
    GAMEBIT_SH_RescuedEggs = 0xA31,                      /* table 1; hint 358; ref hollow/CNTstopwatc target */
    GAMEBIT_TTH_MusicLatch0A32 = 0xA32,                  /* ThornTail Hollow - SH_LevelCon's GameBitLatch condition for music trigger 0x98 */
    GAMEBIT_MMP_GroundAnimaSunk0A35 = 0xA35,             /* Read out of the retail placement data: moonpass/GroundAnima sunkGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_GroundAnimaSunk0A36 = 0xA36,             /* Read out of the retail placement data: moonpass/GroundAnima sunkGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SB_GalleonCycleAPending = 0xA3C,             /* One of the galleon protection minigame's four cycle bits, per SB_Galleon's own aliases - pending and done for cycles A and B; Rena had it only as SBRelated0A3C */
    GAMEBIT_SB_IsRaining = 0xA3D,                        /* table 0. CAUTION: SB_Galleon reads it as cycle B pending, the fourth of the galleon cycle bits 0xA3C/0xA3E/0xA3F - which would make the rain reading either wrong or the same cycle seen from outside */
    GAMEBIT_SB_GalleonCycleADone = 0xA3E,                /* Cycle A of the galleon protection minigame is done, per SB_Galleon's own alias */
    GAMEBIT_SB_GalleonCycleBDone = 0xA3F,                /* Cycle B of the galleon protection minigame is done, per SB_Galleon's own alias */
    GAMEBIT_DR_SeqBit1A0A41 = 0xA41,                     /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/DR_Seqobj objId= param=bit1A; table 0 */
    GAMEBIT_VFP_Open0A42 = 0xA42,                        /* Named from map data alone - nothing in the code or in any name list mentions it: temple/VFP_PodiumP objId= param=open; temple/VFPSeqObj objId= param=bit1A; table 2 */
    GAMEBIT_VFP_ReturnedWithSpellStone = 0xA43,          /* table 2; hint 370; ref temple/HitAnimator target */
    GAMEBIT_DR_ProjectilBit0A44 = 0xA44,                 /* Read out of the retail placement data: dragrock/DRProjectil gameBitId x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_WarpstoneRelated0A45 = 0xA45,                /* table 2; Rena's U0 name - SH_swapston drives the WarpStone's look-at-player behaviour straight from it */
    GAMEBIT_DR_ProjectilBit0A46 = 0xA46,                 /* Read out of the retail placement data: dragrock/DRProjectil gameBitId x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DR_ProjectilBit0A47 = 0xA47,                 /* Read out of the retail placement data: dragrock/DRProjectil gameBitId x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SB_DoorOpen = 0xA4B,                         /* table 0; ref frontend/HitAnimator target */
    GAMEBIT_SC_TotemBondRing4 = 0xA4C,                   /* LightFoot Village totem-bond puzzle - ring slot 4 bonded, gTotemBondRingGameBits[4]; set to 1 when the ring is bonded and passed as the spawned orb's activeGameBit */
    GAMEBIT_SC_TotemBondRing5 = 0xA4D,                   /* LightFoot Village totem-bond puzzle - ring slot 5 bonded, gTotemBondRingGameBits[5]; set to 1 when the ring is bonded and passed as the spawned orb's activeGameBit */
    GAMEBIT_SC_TotemBondRing6 = 0xA4E,                   /* LightFoot Village totem-bond puzzle - ring slot 6 bonded, gTotemBondRingGameBits[6]; set to 1 when the ring is bonded and passed as the spawned orb's activeGameBit */
    GAMEBIT_SC_TotemBondRing7 = 0xA4F,                   /* LightFoot Village totem-bond puzzle - ring slot 7 bonded, gTotemBondRingGameBits[7]; set to 1 when the ring is bonded and passed as the spawned orb's activeGameBit */
    GAMEBIT_SC_TotemBondOrb4 = 0xA50,                    /* LightFoot Village totem-bond puzzle - orb slot 4 consumed, gTotemBondOrbGameBits[4]; the spawned orb's eventGameBit, and slot 4 counts as still available while this reads 0 */
    GAMEBIT_SC_TotemBondOrb5 = 0xA51,                    /* LightFoot Village totem-bond puzzle - orb slot 5 consumed, gTotemBondOrbGameBits[5]; the spawned orb's eventGameBit, and slot 5 counts as still available while this reads 0 */
    GAMEBIT_SC_TotemBondOrb6 = 0xA52,                    /* LightFoot Village totem-bond puzzle - orb slot 6 consumed, gTotemBondOrbGameBits[6]; the spawned orb's eventGameBit, and slot 6 counts as still available while this reads 0 */
    GAMEBIT_SC_TotemBondOrb7 = 0xA53,                    /* LightFoot Village totem-bond puzzle - orb slot 7 consumed, gTotemBondOrbGameBits[7]; the spawned orb's eventGameBit, and slot 7 counts as still available while this reads 0 */
    GAMEBIT_DR_SeqBit180A54 = 0xA54,                     /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/DR_Seqobj objId= param=bit18; table 0 */
    GAMEBIT_DR_Open0A55 = 0xA55,                         /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/DR_CloudDoo objId= param=open; table 1 */
    GAMEBIT_DR_CloudDooClosedLatch0A56 = 0xA56,          /* Read out of the retail placement data: dragrock/DR_CloudDoo closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_WM_DestroyedWall1 = 0xA58,                   /* table 2; cracked wall to inside as Krystal */
    GAMEBIT_WM_Wall1Related0A59 = 0xA59,                 /* table 2; set after blowing up wall */
    GAMEBIT_WM_DestroyedWall2 = 0xA5A,                   /* table 2; past flamethrowers */
    GAMEBIT_WM_Wall2Related0A5B = 0xA5B,                 /* table 2; ref warlock/ExplodeWall onExplode */
    GAMEBIT_ECSH_OpenedDoor_0A5F = 0xA5F,                /* table 2 */
    GAMEBIT_ECSH_PushedSwitch = 0xA60,                   /* table 0; opens 2nd door temporarily */
    GAMEBIT_ECSH_BarrelSpawning = 0xA61,                 /* table 0 */
    GAMEBIT_FinalBoss_ObjGroups = 0xA62,                 /* table 3; size 32 */
    GAMEBIT_WorldMapRelated0A63 = 0xA63,
    GAMEBIT_WorldMapRelated0A64 = 0xA64,
    GAMEBIT_WorldMapRelated0A65 = 0xA65,
    GAMEBIT_WorldMapRelated0A66 = 0xA66,                 /* table 2 */
    GAMEBIT_WorldMapRelated0A67 = 0xA67,
    GAMEBIT_MMP_CFTreasWindActivation0A68 = 0xA68,       /* Read out of the retail placement data: moonpass/CFTreasWind activationGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_CFTreasWindActivation0A69 = 0xA69,       /* Read out of the retail placement data: moonpass/CFTreasWind activationGameBit x1; moonpass/TrigCyl activate x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_CFTreasWindActivation0A6A = 0xA6A,       /* Read out of the retail placement data: moonpass/CFTreasWind activationGameBit x1; moonpass/TrigCyl activate x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_CFTreasWindActivation0A6B = 0xA6B,       /* Read out of the retail placement data: moonpass/CFTreasWind activationGameBit x1; moonpass/TrigCyl activate x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_CFTreasWindActivation0A6C = 0xA6C,       /* Read out of the retail placement data: moonpass/CFTreasWind activationGameBit x1; moonpass/TrigCyl activate x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_ECSH_Shrine0A6D = 0xA6D,                     /* The DLL names this one itself: ECSH_SHRINE_GAMEBIT_0A6D in ECSH_Shrine.c */
    GAMEBIT_ECSH_Shrine0A6F = 0xA6F,                     /* The DLL names this one itself: ECSH_SHRINE_GAMEBIT_0A6F in ECSH_Shrine.c */
    GAMEBIT_ECSH_Shrine0A70 = 0xA70,                     /* The DLL names this one itself: ECSH_SHRINE_GAMEBIT_0A70 in ECSH_Shrine.c */
    GAMEBIT_SfxMute0A71 = 0xA71,                         /* Two DLLs name it and they agree it is the SFX mute - LargeCrate and SB_Galleon both read it that way, and SB_Galleon additionally hangs a GameBitLatch music trigger on it; Rena had it only as SBRelated0A71 */
    GAMEBIT_WM_DestroyedBox1 = 0xA72,                    /* table 2; box blocking ramp at start */
    GAMEBIT_WM_DestroyedBox2 = 0xA74,                    /* table 2 */
    GAMEBIT_WM_DestroyedBox3 = 0xA75,                    /* table 2 */
    GAMEBIT_WM_DestroyedBox4 = 0xA77,                    /* table 2 */
    GAMEBIT_DIM2_LeverActivated0A78 = 0xA78,             /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines2/StaffLeverO objId= param=activated; snowmines2/DIM2SeqObje objId= param=bit1A; table 2 */
    GAMEBIT_MMP_HitAnimTarget0A79 = 0xA79,               /* Named from map data alone - nothing in the code or in any name list mentions it: moonpass/HitAnimator objId= param=target; moonpass/ExplodeWall objId= param=exploded; table 1 */
    GAMEBIT_MMP_OnExplode0A7A = 0xA7A,                   /* Named from map data alone - nothing in the code or in any name list mentions it: moonpass/ExplodeWall objId= param=onExplode; table 1 */
    GAMEBIT_EnableCMenu = 0xA7B,                         /* table 1; set when collecting key on ship */
    GAMEBIT_DIM2_SeqBit180A7D = 0xA7D,                   /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines2/DIM2SeqObje objId= param=bit18; table 2 */
    GAMEBIT_DIM2_HitAnimTarget0A7E = 0xA7E,              /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines2/HitAnimator objId= param=target; snowmines2/DIM2SeqObje objId= param=bit1A; table 2 */
    GAMEBIT_WMRelated0A7F = 0xA7F,                       /* table 3; related to music? toggled constantly in KP */
    GAMEBIT_DIM2_HitAnimTarget0A80 = 0xA80,              /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines2/HitAnimator objId= param=target; snowmines2/DIM2_WallEx objId= param=onExplode; snowmines2/DIM2_WallEx objId= param=exploded; table 2 */
    GAMEBIT_DIM_FlewTo = 0xA82,                          /* table 2; hint 281; ref snowmines/Landed_Arwi Visible */
    GAMEBIT_WM_SeqBit1A0A83 = 0xA83,                     /* Named from map data alone - nothing in the code or in any name list mentions it: warlock/FireHoleCon objId= param=bit1A; warlock/FireHoleCon objId= param=bit1A; table 2 */
    GAMEBIT_VFP_Open0A84 = 0xA84,                        /* Named from map data alone - nothing in the code or in any name list mentions it: temple/VFP_PodiumP objId= param=open; temple/VFP_seqpoin objId= param=_1E; table 2 */
    GAMEBIT_VFP_Open0A85 = 0xA85,                        /* Named from map data alone - nothing in the code or in any name list mentions it: temple/VFP_PodiumP objId= param=open; temple/VFP_seqpoin objId= param=_1E; table 2 */
    GAMEBIT_WM_WallExploded0A87 = 0xA87,                 /* Named from map data alone - nothing in the code or in any name list mentions it: warlock/ExplodeWall objId= param=exploded; warlock/HitAnimator objId= param=target; table 2 */
    GAMEBIT_WM_WallExploded0A88 = 0xA88,                 /* Named from map data alone - nothing in the code or in any name list mentions it: warlock/ExplodeWall objId= param=exploded; warlock/HitAnimator objId= param=target; table 2 */
    GAMEBIT_WM_OnExplode0A89 = 0xA89,                    /* Named from map data alone - nothing in the code or in any name list mentions it: warlock/ExplodeWall objId= param=onExplode; table 2 */
    GAMEBIT_WM_OnExplode0A8A = 0xA8A,                    /* Named from map data alone - nothing in the code or in any name list mentions it: warlock/ExplodeWall objId= param=onExplode; table 2 */
    GAMEBIT_WM_Pressed0A8B = 0xA8B,                      /* Named from map data alone - nothing in the code or in any name list mentions it: warlock/WM_Pressure objId= param=pressed; warlock/CAMERAseqob objId= param=bit1A; table 2 */
    GAMEBIT_WM_Activate0A93 = 0xA93,                     /* Named from map data alone - nothing in the code or in any name list mentions it: warlock/TrigCyl objId= param=activate; table 0 */
    GAMEBIT_WM_WindLiftActivation0A94 = 0xA94,           /* A Warlock Mountain wind-lift activation bit - gWindLiftEnableGameBitTable pairs it with GAMEBIT_Always1, so the lift it activates is unconditionally enabled; Rena places it in warlock */
    GAMEBIT_WM_Activate0A95 = 0xA95,                     /* Named from map data alone - nothing in the code or in any name list mentions it: warlock/TrigCyl objId= param=activate; table 0 */
    GAMEBIT_WM_Activate0A96 = 0xA96,                     /* Named from map data alone - nothing in the code or in any name list mentions it: warlock/TrigCyl objId= param=activate; table 0 */
    GAMEBIT_WM_WindLiftActivation0A98 = 0xA98,           /* A Warlock Mountain wind-lift activation bit - gWindLiftEnableGameBitTable pairs it with GAMEBIT_Always1, so the lift it activates is unconditionally enabled; Rena places it in warlock */
    GAMEBIT_WM_WindLiftActivation0A99 = 0xA99,           /* A Warlock Mountain wind-lift activation bit - gWindLiftEnableGameBitTable pairs it with GAMEBIT_Always1, so the lift it activates is unconditionally enabled; Rena places it in warlock */
    GAMEBIT_NW_FuelCell_A9D = 0xA9D,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_TTH_FuelCell_A9E = 0xA9E,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_WarpStoneUnlockedCC = 0xABA,                 /* table 1; Unused feature where WarpStone would send you to more places. Setting these bits enables an invisble destination menu, b */
    GAMEBIT_WarpStoneUnlockedOFP = 0xABD,                /* table 1 */
    GAMEBIT_WarpStoneUnlockedLV = 0xABE,                 /* table 1 */
    GAMEBIT_WarpStoneUnlockedMMP = 0xABF,                /* table 1 */
    GAMEBIT_WarpStoneUnlockedVFP = 0xAC0,                /* table 1 */
    GAMEBIT_WarpStoneUnlockedIM = 0xAC1,                 /* table 1 */
    GAMEBIT_TTH_FuelCell_AC3 = 0xAC3,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_DR_Open0AC4 = 0xAC4,                         /* Named from map data alone - nothing in the code or in any name list mentions it: trexboss/BossTRexPor objId= param=open; trexboss/BossTRexPor objId= param=open; table 0 */
    GAMEBIT_DR_Open0AC5 = 0xAC5,                         /* Named from map data alone - nothing in the code or in any name list mentions it: trexboss/BossTRexPor objId= param=open; trexboss/BossTRexPor objId= param=open; table 0 */
    GAMEBIT_DR_Open0AC6 = 0xAC6,                         /* Named from map data alone - nothing in the code or in any name list mentions it: trexboss/BossTRexPor objId= param=open; trexboss/BossTRexPor objId= param=open; table 0 */
    GAMEBIT_DR_Open0AC7 = 0xAC7,                         /* Named from map data alone - nothing in the code or in any name list mentions it: trexboss/BossTRexPor objId= param=open; trexboss/BossTRexPor objId= param=open; table 0 */
    GAMEBIT_GalleonDefeated0AC8 = 0xAC8,                 /* SB_Galleon calls it the defeated bit; Rena filed it under WM, and the game has both a WM_Galleon and an SB_Galleon DLL, so the name carries neither prefix */
    GAMEBIT_DIM2_LavaControl0ACD = 0xACD,                /* The DLL names this one itself: DIM2_LAVA_CONTROL_GAMEBIT_0ACD in DIM2LavaCon.c */
    GAMEBIT_CF_StaffBoostACF = 0xACF,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_LargeCrateBroken0AD0 = 0xAD0,             /* Read out of the retail placement data: fortress/LargeCrate brokenGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_Activate0AD1 = 0xAD1,                        /* Named from map data alone - nothing in the code or in any name list mentions it: arwingcloud/TrigBits objId= param=activate; fortress/CFLandingPa objId= param=bit1A; table 1 */
    GAMEBIT_SHOP_Unk0AD3 = 0xAD3,                        /* table 2; set when entering shop */
    GAMEBIT_WM_SeqAD4 = 0xAD4,                           /* Rena's U0 dataset; table 2 */
    GAMEBIT_WM_Open0AD5 = 0xAD5,                         /* Named from map data alone - nothing in the code or in any name list mentions it: warlock/SC_settelme objId= param=open; warlock/CAMERAnewse objId= param=needBit; table 2 */
    GAMEBIT_ITEM_WMGoldKey_Used = 0xADA,                 /* table 2; ref warlock/WM_padlock 0x1C. Backs the collectable item C-menu entry the game labels "Use Gold Key" (its used bit) */
    GAMEBIT_SawBarrelGen = 0xADB,                        /* table 2. BarrelGener names it its triggered bit */
    GAMEBIT_IM_CannonGuy1Dead = 0xADC,                   /* table 2 */
    GAMEBIT_IM_CannonGuy2Dead = 0xADD,                   /* table 2 */
    GAMEBIT_IM_SwitchVisible = 0xADE,                    /* table 0 */
    GAMEBIT_IM_SeqBit180ADF = 0xADF,                     /* Named from map data alone - nothing in the code or in any name list mentions it: newicemount/IMSeqObject objId= param=bit18; table 2 */
    GAMEBIT_DR_HighTop_RidingAE0 = 0xAE0,                /* Rena's kiosk dataset; table 0 */
    GAMEBIT_DFSH_Open0AE1 = 0xAE1,                       /* Named from map data alone - nothing in the code or in any name list mentions it: dfshrine/SC_Shrine_d objId= param=open; table 0 */
    GAMEBIT_DFSH_SCShrinedClosedLatch0AE2 = 0xAE2,       /* Read out of the retail placement data: dfshrine/SC_Shrine_d closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMSH_Shrine0AE4 = 0xAE4,                     /* The DLL names this one itself: MMSH_SHRINE_GAMEBIT_0AE4 in MMSH_Shrine.c */
    GAMEBIT_MMSH_Shrine0AE5 = 0xAE5,                     /* The DLL names this one itself: MMSH_SHRINE_GAMEBIT_0AE5 in MMSH_Shrine.c */
    GAMEBIT_MMSH_Shrine0AE6 = 0xAE6,                     /* The DLL names this one itself: MMSH_SHRINE_GAMEBIT_0AE6 in MMSH_Shrine.c */
    GAMEBIT_CC_Open0AE7 = 0xAE7,                         /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/SC_settelme objId= param=open; capeclaw/StaffLeverO objId= param=activated; capeclaw/CCseqobj objId= param=needBit; table 2 */
    GAMEBIT_GPSH_Pressed0AE8 = 0xAE8,                    /* Named from map data alone - nothing in the code or in any name list mentions it: gpshrine/ECSH_Pressu objId= param=pressed; gpshrine/SC_settelme objId= param=open; table 0 */
    GAMEBIT_GPSH_Open0AE9 = 0xAE9,                       /* Named from map data alone - nothing in the code or in any name list mentions it: gpshrine/SC_settelme objId= param=open; table 0 */
    GAMEBIT_GPSH_Open0AEA = 0xAEA,                       /* Named from map data alone - nothing in the code or in any name list mentions it: gpshrine/SC_settelme objId= param=open; gpshrine/ECSH_Pressu objId= param=pressed; table 0 */
    GAMEBIT_GPSH_CFTreasWindActivation0AEB = 0xAEB,      /* Read out of the retail placement data: gpshrine/CFTreasWind activationGameBit x1; gpshrine/TrigCyl activate x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_GPSH_CFTreasWindActivation0AEC = 0xAEC,      /* Read out of the retail placement data: gpshrine/CFTreasWind activationGameBit x1; gpshrine/TrigCyl activate x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_GPSH_CFTreasWindActivation0AED = 0xAED,      /* Read out of the retail placement data: gpshrine/CFTreasWind activationGameBit x1; gpshrine/TrigCyl activate x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_GPSH_CFTreasWindActivation0AEE = 0xAEE,      /* Read out of the retail placement data: gpshrine/CFTreasWind activationGameBit x1; gpshrine/TrigCyl activate x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_GPSH_CFTreasWindActivation0AEF = 0xAEF,      /* Read out of the retail placement data: gpshrine/CFTreasWind activationGameBit x1; gpshrine/TrigCyl activate x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_GPSH_CFTreasWindActivation0AF1 = 0xAF1,      /* Read out of the retail placement data: gpshrine/CFTreasWind activationGameBit x1; gpshrine/TrigCyl activate x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_GPSH_CFTreasWindActivation0AF2 = 0xAF2,      /* Read out of the retail placement data: gpshrine/CFTreasWind activationGameBit x1; gpshrine/TrigCyl activate x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CC_GoldbarHide0AF3 = 0xAF3,                  /* Read out of the retail placement data: capeclaw/CCgoldbar hideGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CC_GoldbarHide0AF4 = 0xAF4,                  /* Read out of the retail placement data: capeclaw/CCgoldbar hideGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CC_GoldbarHide0AF5 = 0xAF5,                  /* Read out of the retail placement data: capeclaw/CCgoldbar hideGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CC_GoldbarHide0AF6 = 0xAF6,                  /* Read out of the retail placement data: capeclaw/CCgoldbar hideGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_ITEM_CCGoldBar_Count = 0xAF7,                /* table 2; size 3. Backs the collectable item C-menu entry the game labels "Give Gold" (its owned bit) */
    GAMEBIT_CC_GroundAnimaSunk0AF8 = 0xAF8,              /* Read out of the retail placement data: capeclaw/GroundAnima sunkGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CC_GroundAnimaSunk0AF9 = 0xAF9,              /* Read out of the retail placement data: capeclaw/GroundAnima sunkGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CC_GroundAnimaSunk0AFA = 0xAFA,              /* Read out of the retail placement data: capeclaw/GroundAnima sunkGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CC_GroundAnimaSunk0AFB = 0xAFB,              /* Read out of the retail placement data: capeclaw/GroundAnima sunkGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CC_GoldbarCollect0AFC = 0xAFC,               /* Read out of the retail placement data: capeclaw/CCgoldbar collectGameBit x4; 4 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CC_GroundAnimaEnable0AFD = 0xAFD,            /* Read out of the retail placement data: capeclaw/GroundAnima enableGameBit x1; capeclaw/LargeCrate brokenGameBit x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CC_HitAnimTarget0AFE = 0xAFE,                /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/HitAnimator objId= param=target; capeclaw/CCseqobj objId= param=usedBit; table 2 */
    GAMEBIT_GPSH_CFTreasWindActivation0AFF = 0xAFF,      /* Read out of the retail placement data: gpshrine/CFTreasWind activationGameBit x1; gpshrine/TrigCyl activate x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_TrigCylActivate0B01 = 0xB01,                 /* Read out of the retail placement data: gpshrine/CFTreasWind activationGameBit x1; gpshrine/TrigCyl activate x1; hollow/TrigCyl activate x1; 3 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DBSH_CFTreasWindActivation0B03 = 0xB03,      /* Read out of the retail placement data: dbshrine/CFTreasWind activationGameBit x1; dbshrine/TrigCyl activate x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CF_SeqBit1A0B04 = 0xB04,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFseqobject objId= param=bit1A; fortress/SC_Shrine_d objId= param=open; fortress/StaffLeverO objId= param=activated; table 2 */
    GAMEBIT_TTH_FuelCell_B05 = 0xB05,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_TTH_FuelCell_B06 = 0xB06,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_HitAnimTarget0B08 = 0xB08,                /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/HitAnimator objId= param=target; fortress/HitAnimator objId= param=target; table 1 */
    GAMEBIT_CF_HitAnimTarget0B09 = 0xB09,                /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/HitAnimator objId= param=target; fortress/HitAnimator objId= param=target; table 1 */
    GAMEBIT_CF_HitAnimTarget0B0A = 0xB0A,                /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/HitAnimator objId= param=target; fortress/HitAnimator objId= param=target; fortress/HitAnimator objId= param=target (+2 more); table 2 */
    GAMEBIT_CF_Activate0B0B = 0xB0B,                     /* Named from map data alone - nothing in the code or in any name list mentions it: clouddungeon/TrigCyl objId= param=activate; table 2 */
    GAMEBIT_CF_WindLiftRider0B0C = 0xB0C,                /* Read out of the retail placement data: clouddungeon/CFWindLift riderGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CF_Pressed0B0D = 0xB0D,                      /* Named from map data alone - nothing in the code or in any name list mentions it: clouddungeon/CFPressureS objId= param=pressed; table 2 */
    GAMEBIT_CF_HitAnimTarget0B0E = 0xB0E,                /* Named from map data alone - nothing in the code or in any name list mentions it: clouddungeon/ExplodeWall objId= param=exploded; clouddungeon/HitAnimator objId= param=target; clouddungeon/HitAnimator objId= param=target; table 2 */
    GAMEBIT_CF_OnExplode0B0F = 0xB0F,                    /* Named from map data alone - nothing in the code or in any name list mentions it: clouddungeon/ExplodeWall objId= param=onExplode; clouddungeon/CFseqobject objId= param=bit1A; table 2 */
    GAMEBIT_Open0B10 = 0xB10,                            /* Named from map data alone - nothing in the code or in any name list mentions it: gamefront/GF_DoorLeft objId= param=open; greatfox/GF_DoorLeft objId= param=open; table 0 */
    GAMEBIT_GFDoorLeftClosedLatch0B11 = 0xB11,           /* Read out of the retail placement data: gamefront/GF_DoorLeft closedLatchGameBit x1; greatfox/GF_DoorLeft closedLatchGameBit x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_Open0B12 = 0xB12,                            /* Named from map data alone - nothing in the code or in any name list mentions it: gamefront/GF_DoorLeft objId= param=open; greatfox/GF_DoorLeft objId= param=open; table 0 */
    GAMEBIT_GFDoorLeftClosedLatch0B13 = 0xB13,           /* Read out of the retail placement data: gamefront/GF_DoorLeft closedLatchGameBit x1; greatfox/GF_DoorLeft closedLatchGameBit x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DBSH_LeverActivated0B14 = 0xB14,             /* Named from map data alone - nothing in the code or in any name list mentions it: dbshrine/StaffLeverO objId= param=activated; table 0 */
    GAMEBIT_DBSH_HitAnimTarget0B19 = 0xB19,              /* Named from map data alone - nothing in the code or in any name list mentions it: dbshrine/ExplodeWall objId= param=exploded; dbshrine/HitAnimator objId= param=target; dbshrine/HitAnimator objId= param=target; table 0 */
    GAMEBIT_DBSH_OnExplode0B1A = 0xB1A,                  /* Named from map data alone - nothing in the code or in any name list mentions it: dbshrine/ExplodeWall objId= param=onExplode; table 0 */
    GAMEBIT_CF_Open0B1B = 0xB1B,                         /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/SC_Shrine_d objId= param=open; fortress/CNTstopwatc objId= param=enabled; table 1 */
    GAMEBIT_CF_Open0B1C = 0xB1C,                         /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/SC_Shrine_d objId= param=open; fortress/CNTstopwatc objId= param=enabled; table 1 */
    GAMEBIT_CF_Open0B1D = 0xB1D,                         /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/SC_Shrine_d objId= param=open; fortress/CNTstopwatc objId= param=enabled; table 1 */
    GAMEBIT_CF_SeqBit1A0B1E = 0xB1E,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFseqobject objId= param=bit1A; fortress/HitAnimator objId= param=target; fortress/CFExplosive objId= param=open; table 2 */
    GAMEBIT_CF_ExplosiveClosedLatch0B1F = 0xB1F,         /* Read out of the retail placement data: fortress/CFExplosive closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CF_SeqBit180B23 = 0xB23,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFseqobject objId= param=bit18; table 2 */
    GAMEBIT_CC_LevelControlMusicC0 = 0xB24,              /* The DLL names this one itself: CC_LEVEL_CONTROL_MUSIC_C0_GAMEBIT in CClevcontro.c */
    GAMEBIT_CF_SeqBit1A0B25 = 0xB25,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CAMERAseqob objId= param=bit1A; table 1 */
    GAMEBIT_CF_Activate0B26 = 0xB26,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/TrigPln objId= param=activate; table 1 */
    GAMEBIT_CF_SCShrinedClosedLatch0B28 = 0xB28,         /* Read out of the retail placement data: fortress/SC_Shrine_d closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CFRelated0B2A = 0xB2A,                       /* table 1 */
    GAMEBIT_CFRelated0B2B = 0xB2B,                       /* table 1 */
    GAMEBIT_CFRelated0B2C = 0xB2C,                       /* table 1 */
    GAMEBIT_CFRelated0B2D = 0xB2D,                       /* table 1 */
    GAMEBIT_CFRelated0B2E = 0xB2E,                       /* table 1 */
    GAMEBIT_CFRelated0B2F = 0xB2F,                       /* table 1 */
    GAMEBIT_CFRelated0B30 = 0xB30,                       /* table 1 */
    GAMEBIT_CFRelated0B31 = 0xB31,                       /* table 1 */
    GAMEBIT_CFRelated0B32 = 0xB32,                       /* table 1 */
    GAMEBIT_LINKB_LightRelatedB36 = 0xB36,               /* Rena's U0 dataset; table 3. LINKB_levco reads it as the GameBitLatch condition for MUSICTRIG_citytombs, which its own alias spelled CITYTOMBS_MUSIC */
    GAMEBIT_CFRelated0B37 = 0xB37,                       /* table 1 */
    GAMEBIT_CFRelated0B38 = 0xB38,                       /* table 1 */
    GAMEBIT_CFRelated0B39 = 0xB39,                       /* table 1 */
    GAMEBIT_CFRelated0B3A = 0xB3A,                       /* table 1 */
    GAMEBIT_CFRelated0B3B = 0xB3B,                       /* table 1 */
    GAMEBIT_CFRelated0B3C = 0xB3C,                       /* table 1 */
    GAMEBIT_CFRelated0B3D = 0xB3D,                       /* table 1 */
    GAMEBIT_CFRelated0B3E = 0xB3E,                       /* table 1 */
    GAMEBIT_CFRelated0B3F = 0xB3F,                       /* table 1 */
    GAMEBIT_CC_LevelControlBlizzardMusic = 0xB45,        /* The DLL names this one itself: CC_LEVEL_CONTROL_BLIZZARD_MUSIC_GAMEBIT in CClevcontro.c */
    GAMEBIT_CFRelated0B46 = 0xB46,                       /* table 1; ref fortress/CNTstopwatc enabled */
    GAMEBIT_DR_HighTopDrowned = 0xB48,                   /* Raised when HighTop's air meter empties: the DLL shuts the meter down, spawns its death effect and stops the physics */
    GAMEBIT_CF_SeqBit180B49 = 0xB49,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFseqobject objId= param=bit18; table 2 */
    GAMEBIT_CF_ClawDeadB4B = 0xB4B,                      /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_ClawDeadB4C = 0xB4C,                      /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_ClawDeadB4D = 0xB4D,                      /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_ClawDeadB4E = 0xB4E,                      /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_ClawDeadB4F = 0xB4F,                      /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_SCShrinedClosedLatch0B51 = 0xB51,         /* Read out of the retail placement data: fortress/SC_Shrine_d closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CF_ClawDeadB52 = 0xB52,                      /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_ClawDeadB53 = 0xB53,                      /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_Open0B54 = 0xB54,                         /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/SC_Shrine_d objId= param=open; table 2 */
    GAMEBIT_CF_SCShrinedClosedLatch0B55 = 0xB55,         /* Read out of the retail placement data: fortress/SC_Shrine_d closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CF_SeqB56 = 0xB56,                           /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_ForceFielCollapse0B59 = 0xB59,            /* Read out of the retail placement data: fortress/CFForceFiel collapseGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CF_SeqB5A = 0xB5A,                           /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_HitAnimTarget0B62 = 0xB62,                /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/HitAnimator objId= param=target; fortress/HitAnimator objId= param=target; fortress/CFseqobject objId= param=bit1A; table 2 */
    GAMEBIT_CF_SeqB63 = 0xB63,                           /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_SeqB64 = 0xB64,                           /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_FallLadderBase0B66 = 0xB66,               /* Read out of the retail placement data: fortress/Fall_Ladder baseGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CF_FallLadderBase0B67 = 0xB67,               /* Read out of the retail placement data: fortress/Fall_Ladder baseGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CF_PrisonGuaDisable0B68 = 0xB68,             /* Read out of the retail placement data: clouddungeon/CFPrisonGua disableGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CFRelated0B6C = 0xB6C,                       /* table 1 */
    GAMEBIT_DFSH_TestFailed = 0xB70,                     /* table 0; raised where the Test of Combat shrine reaches its post-finish state without success, on the way to reset */
    GAMEBIT_DFSH_Related0B71 = 0xB71,                    /* table 0; the Test of Combat shrine only ever clears it, as part of its reset block */
    GAMEBIT_AlienMusicActive0B72 = 0xB72,                /* Both DLLs that name it agree it is the alien music: LINK_levcon selects MUSICTRIG_mmpassalien off it for its area, and CClevcontro names it the same way, so the name drops either area's prefix */
    GAMEBIT_CC_LevelControlMusicBF = 0xB73,              /* The DLL names this one itself: CC_LEVEL_CONTROL_MUSIC_BF_GAMEBIT in CClevcontro.c */
    GAMEBIT_CF_HitAnimTarget0B74 = 0xB74,                /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/HitAnimator objId= param=target; fortress/HitAnimator objId= param=target; fortress/CFbrokenGra objId= param=exploded; table 2 */
    GAMEBIT_CF_OnExplode0B75 = 0xB75,                    /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFbrokenGra objId= param=onExplode; table 2 */
    GAMEBIT_DFSH_RewardAnimTarget0B76 = 0xB76,           /* Raised as the Test of Combat shrine opens and starts its 0xD2-tick countdown, and cleared on both ways out; Rena has it as dfshrine HitAnimator 0x482BF's target */
    GAMEBIT_DIM2_ClawDeadB77 = 0xB77,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_DIM2_ClawDeadB78 = 0xB78,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_DIM2_ClawDeadB79 = 0xB79,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_DIM2_Open0B7A = 0xB7A,                       /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines2/DIM2PuzzleD objId= param=open; snowmines2/DIM2SeqObje objId= param=bit1A; snowmines2/HitAnimator objId= param=target; table 2 */
    GAMEBIT_DIM2_PuzzleDClosedLatch0B7B = 0xB7B,         /* Read out of the retail placement data: snowmines2/DIM2PuzzleD closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM2_SeqBit180B7C = 0xB7C,                   /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines2/DIM2SeqObje objId= param=bit18; table 2 */
    GAMEBIT_SequenceLatch0B7D = 0xB7D,                   /* Read by DLL 604's sequence case 4, purely to raise that sequence's latch A */
    GAMEBIT_LINKA_ActNo = 0xB81,                         /* table 1; size 4 */
    GAMEBIT_NW_HitAnimTarget0B82 = 0xB82,                /* Named from map data alone - nothing in the code or in any name list mentions it: wastes/HitAnimator objId= param=target; table 2 */
    GAMEBIT_WM_ClawDeadB83 = 0xB83,                      /* Rena's U0 dataset; table 2 */
    GAMEBIT_WM_ClawDeadB84 = 0xB84,                      /* Rena's U0 dataset; table 2 */
    GAMEBIT_WM_ClawDeadB85 = 0xB85,                      /* Rena's U0 dataset; table 2 */
    GAMEBIT_WM_ClawDeadB86 = 0xB86,                      /* Rena's U0 dataset; table 2 */
    GAMEBIT_WM_ClawDeadB88 = 0xB88,                      /* Rena's U0 dataset; table 2 */
    GAMEBIT_OFB_PinPonDeadB8C = 0xB8C,                   /* table 2; Rena's U0 name - DFP_LevelCo gates on it together with 0x792 */
    GAMEBIT_OFB_PinPonDeadB8D = 0xB8D,                   /* Rena's U0 dataset; table 2 */
    GAMEBIT_OFB_Open0B8E = 0xB8E,                        /* Named from map data alone - nothing in the code or in any name list mentions it: kraztest/DFP_Bridge objId= param=open; table 2 */
    GAMEBIT_WM_LargeCrateBroken0B90 = 0xB90,             /* Read out of the retail placement data: warlock/LargeCrate brokenGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_WM_LargeCrateBroken0B91 = 0xB91,             /* Read out of the retail placement data: warlock/LargeCrate brokenGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_WM_LargeCrateBroken0B92 = 0xB92,             /* Read out of the retail placement data: warlock/LargeCrate brokenGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_WM_LargeCrateBroken0B93 = 0xB93,             /* Read out of the retail placement data: warlock/LargeCrate brokenGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CF_DeathGasActive = 0xB97,                   /* table 1; ref fortress/deathGasNoF active */
    GAMEBIT_ITEM_BombSpore_ShowCount = 0xB98,            /* table 2; on HUD */
    GAMEBIT_ITEM_TrickyFood_ShowCount = 0xB99,           /* table 2 */
    GAMEBIT_ITEM_Firefly_ShowCount = 0xB9A,              /* table 2 */
    GAMEBIT_ITEM_MoonSeed_ShowCount = 0xB9B,             /* table 2 */
    GAMEBIT_ITEM_Scarab_ShowCount = 0xB9C,               /* table 2 */
    GAMEBIT_ECSH_TestObservRunning = 0xB9D,              /* table 0; ref ecshrine/HitAnimator target */
    GAMEBIT_CF_BrokenPilClosedLatch0BA3 = 0xBA3,         /* Read out of the retail placement data: fortress/CFBrokenPil closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CF_HitAnimTarget0BA4 = 0xBA4,                /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/HitAnimator objId= param=target; fortress/CFBrokenPil objId= param=open; table 2 */
    GAMEBIT_ECSH_Entered = 0xBA5,                        /* table 1; hint 248; Krystal entered shrine */
    GAMEBIT_WC_PushBlockTimerActive = 0xBA6,             /* Set while either Walled City push-block timed puzzle (A or B) is actively counting down/up; cleared on completion, timeout, or reset; gates the ambient-music latch in wclevelcont_syncProgressBits */
    GAMEBIT_WM_SCsettelmeClosedLatch0BAC = 0xBAC,        /* Read out of the retail placement data: warlock/SC_settelme closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CF_SeqBit180BAE = 0xBAE,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFseqobject objId= param=bit18; fortress/TrigBits objId= param=activate; table 1 */
    GAMEBIT_TestCombatClawDeadB83 = 0xBB3,               /* Rena's U0 dataset; table 0 */
    GAMEBIT_TestCombatClawDeadB84 = 0xBB4,               /* Rena's U0 dataset; table 0 */
    GAMEBIT_TestCombatClawDeadB85 = 0xBB5,               /* Rena's U0 dataset; table 0 */
    GAMEBIT_TestCombatClawDeadB86 = 0xBB6,               /* Rena's U0 dataset; table 0 */
    GAMEBIT_TestCombatClawDeadB88 = 0xBB8,               /* Rena's U0 dataset; table 0 */
    GAMEBIT_TestCombatClawDeadB89 = 0xBB9,               /* Rena's U0 dataset; table 0 */
    GAMEBIT_TestCombatClawDeadB8A = 0xBBA,               /* Rena's U0 dataset; table 0 */
    GAMEBIT_TestCombatClawDeadB8B = 0xBBB,               /* Rena's U0 dataset; table 0 */
    GAMEBIT_TestCombatClawDeadB8C = 0xBBC,               /* Rena's U0 dataset; table 0 */
    GAMEBIT_TestCombatClawDeadB8D = 0xBBD,               /* Rena's U0 dataset; table 0 */
    GAMEBIT_TestCombatClawDeadB8E = 0xBBE,               /* Rena's U0 dataset; table 0 */
    GAMEBIT_TestCombatClawDeadB8F = 0xBBF,               /* Rena's U0 dataset; table 0 */
    GAMEBIT_TestCombatClawDeadBC0 = 0xBC0,               /* Rena's U0 dataset; table 0 */
    GAMEBIT_TestCombatClawDeadBC1 = 0xBC1,               /* Rena's U0 dataset; table 0 */
    GAMEBIT_CR_SpellStoneRelatedBC3 = 0xBC3,             /* Rena's U0 dataset; table 1 */
    GAMEBIT_SeqBit180BC5 = 0xBC5,                        /* Named from map data alone - nothing in the code or in any name list mentions it: cloudrace/CFRaceSeqob objId= param=bit18; fortress/CFseqobject objId= param=bit1A; linki/LINKIseqobj objId= param=bit18; table 1 */
    GAMEBIT_CF_SeqBit180BC6 = 0xBC6,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CFseqobject objId= param=bit18; table 1 */
    GAMEBIT_LINKI_ActNo = 0xBC7,                         /* table 0; This seems wrong... */
    GAMEBIT_WC_FinalStopwatchEnabled = 0xBC8,            /* Wallcity CNTstopwatc 0x49129's enabled param, cleared as the final puzzle completes */
    GAMEBIT_WC_Enabled0BC9 = 0xBC9,                      /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/CNTstopwatc objId= param=enabled; wallcity/CNTstopwatc objId= param=target; table 2 */
    GAMEBIT_WC_Open0BCA = 0xBCA,                         /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/SH_Portcull objId= param=open; wallcity/CNTstopwatc objId= param=target; wallcity/CNTstopwatc objId= param=enabled; table 2 */
    GAMEBIT_WC_Enabled0BCB = 0xBCB,                      /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/CNTstopwatc objId= param=enabled; wallcity/CNTstopwatc objId= param=target; table 2 */
    GAMEBIT_WC_Enabled0BCC = 0xBCC,                      /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/CNTstopwatc objId= param=enabled; wallcity/CNTstopwatc objId= param=target; table 2 */
    GAMEBIT_WC_Open0BCD = 0xBCD,                         /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/SH_Portcull objId= param=open; wallcity/CNTstopwatc objId= param=target; wallcity/CNTstopwatc objId= param=enabled; table 2 */
    GAMEBIT_WC_Open0BCE = 0xBCE,                         /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/SH_Portcull objId= param=open; wallcity/CNTstopwatc objId= param=target; wallcity/CNTstopwatc objId= param=enabled; table 2 */
    GAMEBIT_WC_FinalPuzzleComplete = 0xBCF,              /* The Walled City final puzzle is done - wclevelcont tears down the stopwatch and its animator, saves a checkpoint and raises WCLEVELCTL_FLAG_FINAL, which init reads back from this bit */
    GAMEBIT_WC_FinalAnimTarget0BD0 = 0xBD0,              /* Wallcity HitAnimator 0x4917B's target, cleared as the final puzzle completes */
    GAMEBIT_DRBOT_SeqBit180BDA = 0xBDA,                  /* Named from map data alone - nothing in the code or in any name list mentions it: dragbot/DR_SeqobjBo objId= param=bit18; table 0 */
    GAMEBIT_SC_SteppingClosedLatch0BDB = 0xBDB,          /* Read out of the retail placement data: swapcircle/SC_stepping closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SC_LVBlock3Related0BDC = 0xBDC,              /* One of the three bits sc_levelcontrol raises the moment GAMEBIT_ITEM_LVBlock3_Used is set */
    GAMEBIT_SC_SteppingClosedLatch0BDD = 0xBDD,          /* Read out of the retail placement data: swapcircle/SC_stepping closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_ITEM_LVBlock3_Used = 0xBDE,                  /* table 2; ref swapcircle/SC_blockpla open. Backs the collectable item C-menu entry the game labels "Place Block" (its used bit) */
    GAMEBIT_SC_LVBlock1Related0BDF = 0xBDF,              /* One of the three bits sc_levelcontrol raises the moment GAMEBIT_ITEM_LVBlock1_Used is set; Rena has this one as the target of swapcircle's HitAnimator 0x49433 */
    GAMEBIT_SC_SteppingClosedLatch0BE0 = 0xBE0,          /* Read out of the retail placement data: swapcircle/SC_stepping closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SC_LVBlock1Related0BE1 = 0xBE1,              /* One of the three bits sc_levelcontrol raises the moment GAMEBIT_ITEM_LVBlock1_Used is set */
    GAMEBIT_SC_SteppingClosedLatch0BE2 = 0xBE2,          /* Read out of the retail placement data: swapcircle/SC_stepping closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SC_LVBlock1Related0BE3 = 0xBE3,              /* One of the three bits sc_levelcontrol raises the moment GAMEBIT_ITEM_LVBlock1_Used is set */
    GAMEBIT_SC_SteppingClosedLatch0BE4 = 0xBE4,          /* Read out of the retail placement data: swapcircle/SC_stepping closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_ITEM_LVBlock1_Used = 0xBE5,                  /* table 2; ref swapcircle/SC_blockpla open. Backs the collectable item C-menu entry the game labels "Place Block" (its used bit) */
    GAMEBIT_DrakorCrateBroken0BE6 = 0xBE6,               /* Read out of the retail placement data: finalboss/DrakorCrate brokenGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DrakorCrateBroken0BE7 = 0xBE7,               /* Read out of the retail placement data: finalboss/DrakorCrate brokenGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DrakorCrateBroken0BE8 = 0xBE8,               /* Read out of the retail placement data: finalboss/DrakorCrate brokenGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DrakorCrateBroken0BE9 = 0xBE9,               /* Read out of the retail placement data: finalboss/DrakorCrate brokenGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DrakorCrateBroken0BEA = 0xBEA,               /* Read out of the retail placement data: finalboss/DrakorCrate brokenGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_IM_Unk0BEB = 0xBEB,                          /* table 0; set when first entering */
    GAMEBIT_IM_Unk0BEC = 0xBEC,                          /* table 0; set when first entering */
    GAMEBIT_IM_Unk0BED = 0xBED,                          /* table 0; set when first entering */
    GAMEBIT_IM_Unk0BEE = 0xBEE,                          /* table 0; set when first entering */
    GAMEBIT_IM_Unk0BEF = 0xBEF,                          /* table 0; set when first entering */
    GAMEBIT_DR_CloudRunnerRoute0Active = 0xBF0,          /* Dragon Rock CloudRunner mount - route 0 selector, gDRCloudRunnerGameBitIds[0]; dr_cloudRunner takes the FIRST set bit of the four and steers toward gDRCloudRunnerCurveIds[0] (curve 20) */
    GAMEBIT_DR_CloudRunnerRoute1Active = 0xBF1,          /* Dragon Rock CloudRunner mount - route 1 selector, gDRCloudRunnerGameBitIds[1]; dr_cloudRunner takes the FIRST set bit of the four and steers toward gDRCloudRunnerCurveIds[1] (curve 21) */
    GAMEBIT_DR_CloudRunnerRoute2Active = 0xBF2,          /* Dragon Rock CloudRunner mount - route 2 selector, gDRCloudRunnerGameBitIds[2]; dr_cloudRunner takes the FIRST set bit of the four and steers toward gDRCloudRunnerCurveIds[2] (curve 22) */
    GAMEBIT_DR_CloudRunnerRoute3Active = 0xBF3,          /* Dragon Rock CloudRunner mount - route 3 selector, gDRCloudRunnerGameBitIds[3]; dr_cloudRunner takes the FIRST set bit of the four and steers toward gDRCloudRunnerCurveIds[3] (curve 23) */
    GAMEBIT_CC_SeqBF4 = 0xBF4,                           /* Rena's U0 dataset; table 2 */
    GAMEBIT_CC_SeqBF5 = 0xBF5,                           /* Rena's U0 dataset; table 2 */
    GAMEBIT_CC_HitAnimTarget0BF6 = 0xBF6,                /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/DustMoteSou objId= param=_24; capeclaw/HitAnimator objId= param=target; capeclaw/HitAnimator objId= param=target; table 2 */
    GAMEBIT_DR_HighTopAirMeterRelated0BF7 = 0xBF7,       /* Cleared when HighTop's air meter empties, but only in the v1.1 builds - the v1.0 DOLs have no write of it at all */
    GAMEBIT_SH_initObjGroups = 0xBF8,                    /* table 0 */
    GAMEBIT_ITEM_TestCombatSpirit_Got = 0xBFD,           /* table 2; hint 312 */
    GAMEBIT_TTH_MusicLatch0BFE = 0xBFE,                  /* ThornTail Hollow - SH_LevelCon's GameBitLatch condition for music trigger 0xC3 */
    GAMEBIT_DIM2_HitAnimTarget0BFF = 0xBFF,              /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines2/HitAnimator objId= param=target; snowmines2/HitAnimator objId= param=target; snowmines2/HitAnimator objId= param=target (+2 more); table 2 */
    GAMEBIT_DRBOT_Activate0C0F = 0xC0F,                  /* Named from map data alone - nothing in the code or in any name list mentions it: dragbot/TrigBits objId= param=activate; table 0 */
    GAMEBIT_SC_TotemPuzzleActivated = 0xC10,             /* The DLL names this one itself: SC_TOTEM_PUZZLE_GAMEBIT_ACTIVATED in SC_totempuz.c */
    GAMEBIT_MaybeHaveTricky = 0xC11,                     /* table 2; maybe wrong */
    GAMEBIT_DIM_HitAnimTarget0C14 = 0xC14,               /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/HitAnimator objId= param=target; snowmines/DIMWoodDoor objId= param=open; table 2 */
    GAMEBIT_DIM_HitAnimTarget0C15 = 0xC15,               /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/HitAnimator objId= param=target; snowmines/DIMWoodDoor objId= param=open; snowmines/CAMERAseqob objId= param=bit1A; table 2 */
    GAMEBIT_DIM_WoodDoorClosedLatch0C16 = 0xC16,         /* Read out of the retail placement data: snowmines/DIMWoodDoor closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM_CannonRelated0C17 = 0xC17,               /* table 2; related to DIM cannon */
    GAMEBIT_DIM_ClawDeadC18 = 0xC18,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_DIM_ClawDeadC19 = 0xC19,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_DIM_ClawDeadC1A = 0xC1A,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_DIM_ClawDeadC1B = 0xC1B,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_DIM_ClawDeadC1C = 0xC1C,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_DIM_ClawDeadC1D = 0xC1D,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_DIM_MusicLatch0C1E = 0xC1E,                  /* DIM_LevelCo's GameBitLatch condition for MUSICTRIG_drako_1 and MUSICTRIG_citytombs_ed, cleared by 0x1A7 when set and by GAMEBIT_SH_Landed064B when clear; DIMboss_free raises it as the fight tears down, which is how the area music comes back */
    GAMEBIT_DIM_WarpActive0C1F = 0xC1F,                  /* DarkIce's warp-in-progress bit, joining GAMEBIT_WarpActive0393 and its kin: DIM_LevelCo makes it the latch condition for MUSICTRIG_Teleport and for its own 0xCF track. DIMboss_free and the player's bike mount both clear it */
    GAMEBIT_DIM_AmbientMusicLatch0C20 = 0xC20,           /* DIM_LevelCo's latch condition for whichever of its day/night ambient tracks is current, and for its 0x35 track; cleared by DIMboss_free on teardown */
    GAMEBIT_DR_Collected0C22 = 0xC22,                    /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/ExplodePlan objId= param=collected; dragrock/ExplodePlan objId= param=exploded; table 2 */
    GAMEBIT_DR_OnExplode0C23 = 0xC23,                    /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/ExplodePlan objId= param=onExplode; table 2 */
    GAMEBIT_ITEM_LVBlock1_Got = 0xC25,                   /* table 2; ref swapcircle/SC_blockpla key. Backs the collectable item C-menu entry the game labels "Place Block" (its owned bit) */
    GAMEBIT_ITEM_LVBlock2_Got = 0xC26,                   /* table 2; ref swapcircle/SC_blockpla key. Backs the collectable item C-menu entry the game labels "Place Block" (its owned bit) */
    GAMEBIT_ITEM_LVBlock3_Got = 0xC27,                   /* table 2; ref swapcircle/SC_blockpla key. Backs the collectable item C-menu entry the game labels "Place Block" (its owned bit) */
    GAMEBIT_SC_GroundAnimaSunk0C28 = 0xC28,              /* Read out of the retail placement data: swapcircle/GroundAnima sunkGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SC_GroundAnimaSunk0C29 = 0xC29,              /* Read out of the retail placement data: swapcircle/GroundAnima sunkGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SC_GroundAnimaSunk0C2A = 0xC2A,              /* Read out of the retail placement data: swapcircle/GroundAnima sunkGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM2_ClawDeadC2B = 0xC2B,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_DIM2_DIMCannonHold0C2C = 0xC2C,              /* Read out of the retail placement data: snowmines2/DIMCannon holdGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CannonRelated0C2D = 0xC2D,                   /* table 2 */
    GAMEBIT_CannonRelated0C2E = 0xC2E,                   /* table 2 */
    GAMEBIT_PlayerIsDisguised = 0xC30,                   /* table 0 */
    GAMEBIT_NW_Open0C31 = 0xC31,                         /* Named from map data alone - nothing in the code or in any name list mentions it: wastes/NW_Portcull objId= param=open; table 2 */
    GAMEBIT_WC_RedEyeDeadC32 = 0xC32,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_WC_RedEyeDeadC33 = 0xC33,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_WC_RedEyeDeadC34 = 0xC34,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_WC_RedEyeDeadC35 = 0xC35,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_WC_EarthWalkerTopic0C36 = 0xC36,             /* One rung of the Walled City EarthWalker's topic chain, picked when the rung above it is clear; Rena has it as wallcity HitAnimator 0x49935's target */
    GAMEBIT_WC_FinalSequenceReward = 0xC37,              /* Walled City - set when the final sequence completes; Rena records it as the target of wallcity's HitAnimator */
    GAMEBIT_LV_ChallengeGate1Baby0Delivered = 0xC38,     /* LightFoot challenge gate 1 (ident 0x46A51) - first of the three baby-LightFoot 'delivered' flags it requires; the trio gated by GAMEBIT_LV_ChallengeGate1BabiesActive carries these (pairing is by elimination, gate 1's trio has no inline triple check) */
    GAMEBIT_LV_ChallengeGate1Baby1Delivered = 0xC39,     /* LightFoot challenge gate 1 - second baby-LightFoot delivered flag */
    GAMEBIT_LV_ChallengeGate1Baby2Delivered = 0xC3A,     /* LightFoot challenge gate 1 - third baby-LightFoot delivered flag */
    GAMEBIT_LV_ChallengeGate2Baby0Delivered = 0xC3B,     /* LightFoot challenge gate 2 (ident 0x46A55) - first of its three baby-LightFoot delivered flags; 437.c sets one per baby of the 0x499AC/AE/AF trio when the player carries it within 25 units of object 0x499B5, and plays the 'all three' jingle once this triple is complete */
    GAMEBIT_LV_ChallengeGate2Baby1Delivered = 0xC3C,     /* LightFoot challenge gate 2 - second baby-LightFoot delivered flag */
    GAMEBIT_LV_ChallengeGate2Baby2Delivered = 0xC3D,     /* LightFoot challenge gate 2 - third baby-LightFoot delivered flag */
    GAMEBIT_SC_ChallengeGate3Baby0Delivered = 0xC3E,     /* LightFoot challenge gate 3 (ident 0x49928) - first of its three baby-LightFoot delivered flags; the 0x499B0/B1/B2 trio delivers to object 0x499B6 */
    GAMEBIT_SC_ChallengeGate3Baby1Delivered = 0xC3F,     /* LightFoot challenge gate 3 - second baby-LightFoot delivered flag */
    GAMEBIT_SC_ChallengeGate3Baby2Delivered = 0xC40,     /* LightFoot challenge gate 3 - third baby-LightFoot delivered flag */
    GAMEBIT_SC_MusicTreeGate1 = 0xC41,                   /* The DLL names this one itself: SC_MUSIC_TREE_GAMEBIT_GATE_1 in 439.c */
    GAMEBIT_LV_ChallengeGate2BabiesActive = 0xC42,       /* Challenge gate 2's baby-LightFoot trio (idents 0x499AC/AE/AF) is in play; while clear, 437.c hides and un-hits each of those babies instead of tracking its delivered flag */
    GAMEBIT_SC_MusicTreeGate2 = 0xC43,                   /* The DLL names this one itself: SC_MUSIC_TREE_GAMEBIT_GATE_2 in 439.c */
    GAMEBIT_LV_ChallengeGate1BabiesActive = 0xC44,       /* Challenge gate 1's baby-LightFoot trio (idents 0x4993F-0x49941) is in play; the gate-1 counterpart of GAMEBIT_LV_ChallengeGate2BabiesActive */
    GAMEBIT_SC_MusicTreeGate3 = 0xC45,                   /* The DLL names this one itself: SC_MUSIC_TREE_GAMEBIT_GATE_3 in 439.c */
    GAMEBIT_SC_ChallengeGate3BabiesActive = 0xC46,       /* Challenge gate 3's baby-LightFoot trio (idents 0x499B0-0x499B2) is in play */
    GAMEBIT_CC_LevelControlDayNightMusic = 0xC47,        /* The DLL names this one itself: CC_LEVEL_CONTROL_DAY_NIGHT_MUSIC_GAMEBIT in CClevcontro.c */
    GAMEBIT_SH_QueenQuestComplete0C48 = 0xC48,           /* Top of the Queen EarthWalker's event-table chain: while set she uses the same completed table GAMEBIT_SH_RescuedEggs selects, ahead of every portal state */
    GAMEBIT_LV_ChallengeGate1TargetHit = 0xC49,          /* One-shot: challenge gate 1's reward sequence has been seen through to its target hit - Lightfoot_RecordCompletedChallengeTargetHit latches it once challengeCompletePending is up and the hit flag arrives */
    GAMEBIT_LV_ChallengeGate2TargetHit = 0xC4A,          /* One-shot: challenge gate 2's reward sequence reached its target hit */
    GAMEBIT_SC_ChallengeGate3TargetHit = 0xC4B,          /* One-shot: challenge gate 3's reward sequence reached its target hit */
    GAMEBIT_SC_SeqBit180C4C = 0xC4C,                     /* Named from map data alone - nothing in the code or in any name list mentions it: swapcircle/SC_sequence objId= param=bit18; table 2 */
    GAMEBIT_SC_SeqBit180C4D = 0xC4D,                     /* Named from map data alone - nothing in the code or in any name list mentions it: swapcircle/SC_sequence objId= param=bit18; table 2 */
    GAMEBIT_SC_Enabled0C4E = 0xC4E,                      /* Named from map data alone - nothing in the code or in any name list mentions it: swapcircle/StaffBoostP objId= param=enabled; swapcircle/SC_sequence objId= param=bit18; table 2 */
    GAMEBIT_CC_SfxPlayerBit0C4F = 0xC4F,                 /* Read out of the retail placement data: capeclaw/sfxPlayer gameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SC_Open0C50 = 0xC50,                         /* Named from map data alone - nothing in the code or in any name list mentions it: swapcircle/SC_hutdoor objId= param=open; table 2 */
    GAMEBIT_SC_HutdoorClosedLatch0C51 = 0xC51,           /* Read out of the retail placement data: swapcircle/SC_hutdoor closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_LV_ChallengeGate1Complete = 0xC52,           /* challenge-gate NPC 1 reward latch (ident 0x46A51) */
    GAMEBIT_LV_ChallengeGate2Complete = 0xC53,           /* One-shot reward latch for LightFoot Village challenge-gate NPC 2 (ident 0x46A55): fires once bits 0xc3b/0xc3c/0xc3d (the three baby-lightfoot-delivered flags) are all set, permanently disabling that NPC's interaction and unlocking swapcircle map objgroup 0xa */
    GAMEBIT_SC_ChallengeGate3Complete = 0xC54,           /* One-shot latch: Lightfoot Village's third target-hit challenge gate (encounterType 0x49928) has been completed and its reward sequence (7) already played */
    GAMEBIT_ITEM_SuperQuake_Got = 0xC55,                 /* table 2; hint 364; ref wallcity/MagicCaveTo Collected. Backs the staff ability C-menu entry the game labels "Ground Quake" (its used bit); and the staff ability C-menu entry the game labels "Super Quake" (its owned bit) */
    GAMEBIT_WC_Switch1Activated = 0xC58,                 /* Walled City floor switch 1 activated; wclevelcont_updateAct2State chimes once on the rising edge (dialogueFlags.b40) and needs all of 0xC58/0xC59/0xC5A for GAMEBIT_WC_AllSwitchesActivated */
    GAMEBIT_WC_Switch2Activated = 0xC59,                 /* Walled City floor switch 2 activated; chimes once via dialogueFlags.b20, counts toward GAMEBIT_WC_AllSwitchesActivated */
    GAMEBIT_WC_Switch3Activated = 0xC5A,                 /* Walled City floor switch 3 activated; chimes once via dialogueFlags.b18, counts toward GAMEBIT_WC_AllSwitchesActivated */
    GAMEBIT_LINKF_TexScrollC5B = 0xC5B,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_LINKF_TexScrollC5C = 0xC5C,                  /* Rena's U0 dataset; table 0 */
    GAMEBIT_LINKF_Open0C5D = 0xC5D,                      /* Named from map data alone - nothing in the code or in any name list mentions it: linkf/LINK_Portcu objId= param=open; table 0 */
    GAMEBIT_LINKF_Open0C5E = 0xC5E,                      /* Named from map data alone - nothing in the code or in any name list mentions it: linkf/LINK_Portcu objId= param=open; table 0 */
    GAMEBIT_DIM2_ConveyorDirectionSwapEnabled = 0xC61,   /* The DLL names this one itself: DIM2CONVEYOR_GAMEBIT_DIRECTION_SWAP_ENABLED in DIM2Conveyo.c */
    GAMEBIT_DR_SeqBit180C63 = 0xC63,                     /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/DR_Seqobj objId= param=bit18; table 2 */
    GAMEBIT_ITEM_Viewfinder_Got = 0xC64,                 /* table 2; hint 409; aka High-Defnition Display Device or Zoom Goggles */
    GAMEBIT_LINKC_SeqNeed0C65 = 0xC65,                   /* Named from map data alone - nothing in the code or in any name list mentions it: linkc/StaffLeverT objId= param=activated; linkc/LINKC_seqob objId= param=needBit; linkc/LINKC_seqob objId= param=needBit; table 2 */
    GAMEBIT_LINKC_Disable0C66 = 0xC66,                   /* Named from map data alone - nothing in the code or in any name list mentions it: linkc/CCriverflow objId= param=disable; linkc/CCriverflow objId= param=disable; linkc/CCriverflow objId= param=disable (+38 more); table 2 */
    GAMEBIT_DR_Related0C67 = 0xC67,                      /* Read by DLL 620: while set, the object tests its X against a narrow window and raises either its placement's own openedGameBit or GAMEBIT_DR_ChimneyReset0EA4 */
    GAMEBIT_LINKC_HitAnimTarget0C68 = 0xC68,             /* Named from map data alone - nothing in the code or in any name list mentions it: linkc/LINK_Portcu objId= param=open; linkc/HitAnimator objId= param=target; linkc/HitAnimator objId= param=target; table 2 */
    GAMEBIT_LINKC_LINKPortcuClosedLatch0C6A = 0xC6A,     /* Read out of the retail placement data: linkc/LINK_Portcu closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_LINKC_LINKPortcuClosedLatch0C6B = 0xC6B,     /* Read out of the retail placement data: linkc/LINK_Portcu closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_ITEM_SpiritTestStrength_Got = 0xC6E,         /* table 2; hint 380 */
    GAMEBIT_ITEM_Spirit4_Used = 0xC70,                   /* table 2; hint 382 */
    GAMEBIT_WM_SpiritPlace4Ready = 0xC71,                /* table 2; gates spirit-place 4 and its return pad */
    GAMEBIT_DBSH_Shrine0C72 = 0xC72,                     /* The DLL names this one itself: DBSH_SHRINE_GAMEBIT_0C72 in DBSH_Shrine.c */
    GAMEBIT_DBSH_Shrine0C73 = 0xC73,                     /* The DLL names this one itself: DBSH_SHRINE_GAMEBIT_0C73 in DBSH_Shrine.c */
    GAMEBIT_LINKJ_SeqNeed0C75 = 0xC75,                   /* Named from map data alone - nothing in the code or in any name list mentions it: linkj/LINKJseqobj objId= param=needBit; linkj/SC_Shrine_d objId= param=open; table 2 */
    GAMEBIT_LINKJ_HitAnimTarget0C76 = 0xC76,             /* Named from map data alone - nothing in the code or in any name list mentions it: linkj/HitAnimator objId= param=target; table 2 */
    GAMEBIT_LINKJ_HitAnimTarget0C77 = 0xC77,             /* Named from map data alone - nothing in the code or in any name list mentions it: linkj/HitAnimator objId= param=target; table 1 */
    GAMEBIT_LINKJ_XYZAnimatorCompletion0C78 = 0xC78,     /* Read out of the retail placement data: linkj/XYZAnimator completionGameBit x3; 3 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DRBOT_DRDrakorDoClosedLatch0C79 = 0xC79,     /* Read out of the retail placement data: dragbot/DR_DrakorDo closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_LINKJ_Open0C7A = 0xC7A,                      /* Named from map data alone - nothing in the code or in any name list mentions it: linkj/SC_Shrine_d objId= param=open; linkj/HitAnimator objId= param=target; table 2 */
    GAMEBIT_LINKJ_SCShrinedClosedLatch0C7B = 0xC7B,      /* Read out of the retail placement data: linkj/SC_Shrine_d closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_ITEM_RockCandy_Got = 0xC7C,                  /* table 2. Backs the collectable item C-menu entry the game labels "Give Gift" (its owned bit) */
    GAMEBIT_ITEM_RockCandy_Used = 0xC7D,                 /* table 2; hint 258. Backs the collectable item C-menu entry the game labels "Give Gift" (its used bit) */
    GAMEBIT_SH_WarpStoneComplainingAboutGifts = 0xC7E,   /* table 2; triggers "nobody brings me gifts" scene */
    GAMEBIT_LINKJ_Open0C7F = 0xC7F,                      /* Named from map data alone - nothing in the code or in any name list mentions it: linkj/SC_Shrine_d objId= param=open; linkj/HitAnimator objId= param=target; table 2 */
    GAMEBIT_LINKJ_SCShrinedClosedLatch0C80 = 0xC80,      /* Read out of the retail placement data: linkj/SC_Shrine_d closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CD_SeqC81 = 0xC81,                           /* Rena's U0 dataset; table 2 */
    GAMEBIT_OFB_LeverActivated0C82 = 0xC82,              /* Named from map data alone - nothing in the code or in any name list mentions it: kraztest/StaffLeverO objId= param=activated; table 2 */
    GAMEBIT_DFSH_ObjGroups = 0xC84,                      /* table 3; size 32 */
    GAMEBIT_ITEM_Spirit5_Got = 0xC85,                    /* table 2; hint 417 */
    GAMEBIT_CF_BitIncOnDeath0C86 = 0xC86,                /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/GCRobotPatr objId= param=bit_incOnDeath; fortress/GCRobotPatr objId= param=bit_incOnDeath; fortress/GCRobotPatr objId= param=bit_incOnDeath; table 1 */
    GAMEBIT_LINKE_CFTreasWindActivation0C88 = 0xC88,     /* Read out of the retail placement data: linke/CFTreasWind activationGameBit x1; linke/TrigCyl activate x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_LINKE_CFTreasWindActivation0C89 = 0xC89,     /* Read out of the retail placement data: linke/CFTreasWind activationGameBit x1; linke/TrigCyl activate x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_LINKE_CFTreasWindActivation0C8A = 0xC8A,     /* Read out of the retail placement data: linke/CFTreasWind activationGameBit x1; linke/TrigCyl activate x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_LINKE_TunnelOpen = 0xC8B,                    /* table 2; broke open wind tunnel in LinkE */
    GAMEBIT_LINKE_OnExplode0C8C = 0xC8C,                 /* Named from map data alone - nothing in the code or in any name list mentions it: linke/LINKE_Explo objId= param=onExplode; table 2 */
    GAMEBIT_ITEM_PDA_Got = 0xC8D,                        /* table 2; Set when landing at TTH. Backs the collectable item C-menu entry the game labels "PDA On/Off" (its owned bit) */
    GAMEBIT_LINKI_Open0C8E = 0xC8E,                      /* Named from map data alone - nothing in the code or in any name list mentions it: linki/SC_settelme objId= param=open; table 2 */
    GAMEBIT_WC_SeqBit1A0C8F = 0xC8F,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit1A; table 2 */
    GAMEBIT_WC_EarthWalkerTopic0C90 = 0xC90,             /* The rung above GAMEBIT_WC_EarthWalkerTopic0C36 in the Walled City EarthWalker's topic chain */
    GAMEBIT_GPSH_TestKnowledgeCompleted = 0xC91,         /* set when the Test of Knowledge succeeds; GPSH free keeps the shrine music lock active until this bit is set */
    GAMEBIT_Tricky_SaidGoodBye = 0xC92,                  /* table 2; hint 418 */
    GAMEBIT_SHBOT_HitAnimTarget0C93 = 0xC93,             /* Named from map data alone - nothing in the code or in any name list mentions it: hollow2/HitAnimator objId= param=target; hollow2/HitAnimator objId= param=target; hollow2/SH_BottomSe objId= param=needBit; table 2 */
    GAMEBIT_SHBOT_HitAnimTarget0C94 = 0xC94,             /* Named from map data alone - nothing in the code or in any name list mentions it: hollow2/HitAnimator objId= param=target; hollow2/ExplodeWall objId= param=exploded; table 2 */
    GAMEBIT_SHBOT_HitAnimTarget0C95 = 0xC95,             /* Named from map data alone - nothing in the code or in any name list mentions it: hollow2/HitAnimator objId= param=target; hollow2/ExplodeWall objId= param=exploded; table 2 */
    GAMEBIT_SHBOT_OnExplode0C97 = 0xC97,                 /* Named from map data alone - nothing in the code or in any name list mentions it: hollow2/ExplodeWall objId= param=onExplode; table 2 */
    GAMEBIT_SHBOT_OnExplode0C98 = 0xC98,                 /* Named from map data alone - nothing in the code or in any name list mentions it: hollow2/ExplodeWall objId= param=onExplode; table 2 */
    GAMEBIT_SHBOT_BombPlantedC99 = 0xC99,                /* Rena's U0 dataset; table 2 */
    GAMEBIT_SHBOT_BombPlantedC9A = 0xC9A,                /* Rena's U0 dataset; table 2 */
    GAMEBIT_SHBOT_BombPlantedC9B = 0xC9B,                /* Rena's U0 dataset; table 2 */
    GAMEBIT_SHBOT_SeqC9E = 0xC9E,                        /* Rena's U0 dataset; table 2 */
    GAMEBIT_SHBOT_SHPortcullOpen0C9F = 0xC9F,            /* Read out of the retail placement data: hollow2/SH_Portcull open x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_ITEM_CCGoldBar1_NotReturned = 0xCA3,         /* table 2 */
    GAMEBIT_ITEM_CCGoldBar2_NotReturned = 0xCA4,         /* table 2 */
    GAMEBIT_ITEM_CCGoldBar3_NotReturned = 0xCA5,         /* table 2 */
    GAMEBIT_ITEM_CCGoldBar4_NotReturned = 0xCA6,         /* table 2 */
    GAMEBIT_WC_FinalSequenceComplete = 0xCAC,            /* Walled City final sequence finished; wclevelcont polls it in MODE_SEQUENCE to clear the stopwatch bit, set GAMEBIT_WC_FinalSequenceReward, save a checkpoint and move to MODE_DONE, and separately latches WCLEVELCTL_FLAG_EXTRA */
    GAMEBIT_OFB_LeverEnabledCB1 = 0xCB1,                 /* Rena's U0 dataset; table 2 */
    GAMEBIT_IM_BombPlanted = 0xCB2,                      /* table 2; in front of cheat well cave */
    GAMEBIT_IM_OpenedCheatWell = 0xCB3,                  /* table 2; ref newicemount/HitAnimator target */
    GAMEBIT_IM_CheatWellCaveRelated0CB4 = 0xCB4,         /* table 2; ref newicemount/ExplodeWall onExplode */
    GAMEBIT_ITEM_Spirit5_Released = 0xCB5,               /* table 2; hint 420 */
    GAMEBIT_WM_SpiritPlace5Ready = 0xCB6,                /* table 2; gates spirit-place 5 and its return pad */
    GAMEBIT_ITEM_Spirit6_Released = 0xCB7,               /* table 2; hint 423; hint: "Andross Revealed" */
    GAMEBIT_WM_SpiritPlace6Ready = 0xCB8,                /* table 2; gates spirit-place 6 and its return pad */
    GAMEBIT_OFB_DFPseqpoinDisable0CB9 = 0xCB9,           /* A DFP sequence point's disable bit, from its placement's field at 0x20. Two of the ids that slot holds - 0xCB1 and 0xEE0 - were already named from other evidence, which is what vindicates the slot; DfpSeqPointPlacement overruns the 0x24 record at its tail, but this field is inside it */
    GAMEBIT_SHRINE_MUSIC_LOCK = 0xCBB,                   /* Krazoa-shrine music lock: set (success-gated in GPSH) when a Krazoa shrine object (MMSH/ECSH/DFSH/DBSH/GPSH) frees; every area's level-control DLL watches it via GameBitLatch_Update to start/stop MUSICTRIG_PU3_Adventure_c4 and hand back its own ambient music, and it also raises audio.c's SFX reverb bus and suppresses doorf4's door-close SFX during the transition */
    GAMEBIT_ITEM_SpellStone_Disabled = 0xCBC,            /* table 2; dims them in the menu. Backs the collectable item C-menu entry the game labels "Use SpellStone" (its active bit) */
    GAMEBIT_SawFuelCell = 0xCBE,                         /* table 2 */
    GAMEBIT_SB_KrystalBoardedGalleon = 0xCBF,            /* table 0; hint 245 */
    GAMEBIT_SawBafomdad = 0xCC0,                         /* table 2 */
    GAMEBIT_GF_ActNo = 0xCC2,                            /* table 1; size 4 */
    GAMEBIT_DIM2_LavaControl0CC3 = 0xCC3,                /* The DLL names this one itself: DIM2_LAVA_CONTROL_GAMEBIT_0CC3 in DIM2LavaCon.c */
    GAMEBIT_GF_PepperTalking = 0xCC5,                    /* table 0 */
    GAMEBIT_SHBOT_HitAnimTarget0CC6 = 0xCC6,             /* Named from map data alone - nothing in the code or in any name list mentions it: hollow2/ExplodeWall objId= param=exploded; hollow2/HitAnimator objId= param=target; hollow2/HitAnimator objId= param=target; table 2 */
    GAMEBIT_SHBOT_OnExplode0CC8 = 0xCC8,                 /* Named from map data alone - nothing in the code or in any name list mentions it: hollow2/ExplodeWall objId= param=onExplode; table 2 */
    GAMEBIT_SHBOT_BombPlantedCCA = 0xCCA,                /* Rena's U0 dataset; table 2 */
    GAMEBIT_StaffPowerupAnimRunning = 0xCCC,             /* table 0; set when collecting an upgrade */
    GAMEBIT_MusicLatch0CCD = 0xCCD,                      /* No reader anywhere in the code and no map objref; the only evidence is KT_RexLevel_free clearing it on arena teardown beside GAMEBIT_SETPIECE_ACTIVE, GAMEBIT_SHRINE_MUSIC_LOCK and the neighbouring music-latch conditions 0xCCE/0xCD0, so it is named for the band it sits in */
    GAMEBIT_WC_WarpActive0CCE = 0xCCE,                   /* Walled City's own warp-in-progress bit - WCLevelCont makes it the GameBitLatch condition their level controllers attach to MUSICTRIG_Teleport (0x36, track 85 SNGTeleport) */
    GAMEBIT_MusicLatch0CCF = 0xCCF,                      /* As GAMEBIT_MusicLatch0CCD: named for its band, on the strength of KT_RexLevel_free alone */
    GAMEBIT_WC_MusicLatch0CD0 = 0xCD0,                   /* WCLevelCont's GameBitLatch condition for music trigger 0xD4, whose track this project has not yet identified; KT_RexLevel_free clears it on teardown */
    GAMEBIT_MusicLatch0CD1 = 0xCD1,                      /* As GAMEBIT_MusicLatch0CCD: named for its band, on the strength of KT_RexLevel_free alone */
    GAMEBIT_SHBOT_SeqUsed0CD3 = 0xCD3,                   /* Named from map data alone - nothing in the code or in any name list mentions it: hollow2/SH_BottomSe objId= param=usedBit; table 2 */
    GAMEBIT_SHBOT_HitAnimTarget0CD4 = 0xCD4,             /* Named from map data alone - nothing in the code or in any name list mentions it: hollow2/HitAnimator objId= param=target; table 2 */
    GAMEBIT_SH_ThornTailRelated0CD5 = 0xCD5,             /* table 2; probably "talked to guy who tells you to get a lantern" */
    GAMEBIT_SH_ThornTailRelated0CD6 = 0xCD6,             /* table 2 */
    GAMEBIT_SHBOT_SHboulderBit0CD8 = 0xCD8,              /* Read out of the retail placement data: hollow2/SH_boulder gameBit x1 */
    GAMEBIT_SHBOT_SeqUsed0CD9 = 0xCD9,                   /* Named from map data alone - nothing in the code or in any name list mentions it: hollow2/SH_BottomSe objId= param=usedBit; table 2 */
    GAMEBIT_SHOP_FogControlEnable0CDA = 0xCDA,           /* Read out of the retail placement data: swapstore/fogControl enableGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_LINKC_HitAnimTarget0CDB = 0xCDB,             /* Named from map data alone - nothing in the code or in any name list mentions it: linkc/LINK_Portcu objId= param=open; linkc/HitAnimator objId= param=target; linkc/HitAnimator objId= param=target; table 2 */
    GAMEBIT_SC_HelpTextEnabled = 0xCDC,                  /* While set, sc_levelcontrol shows game text 0x429 for the first 300 frames the player is in swapcircle */
    GAMEBIT_NW_ReturnedTo = 0xCE1,                       /* table 2; hint 277 */
    GAMEBIT_VFP_HitAnimTarget0CE2 = 0xCE2,               /* Named from map data alone - nothing in the code or in any name list mentions it: temple/HitAnimator objId= param=target; temple/CAMERAseqob objId= param=bit1A; table 2 */
    GAMEBIT_VFP_ClawDeadCE3 = 0xCE3,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_ClawDeadCE4 = 0xCE4,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_ClawDeadCE5 = 0xCE5,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_ClawDeadCE6 = 0xCE6,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_SeqBit180CE7 = 0xCE7,                    /* Named from map data alone - nothing in the code or in any name list mentions it: temple/CAMERAseqob objId= param=bit18; table 2 */
    GAMEBIT_VFP_ClawAliveCE8 = 0xCE8,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_ClawAliveCE9 = 0xCE9,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_ClawAliveCEA = 0xCEA,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_ClawAliveCEB = 0xCEB,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_ClawAliveCEC = 0xCEC,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_BitClearOnDeath0CED = 0xCED,             /* Named from map data alone - nothing in the code or in any name list mentions it: temple/sharpclawSo objId= param=bit_clearOnDeath; table 2 */
    GAMEBIT_SHOP_Unk0CEF = 0xCEF,                        /* table 0; set when entering shop, cleared when leaving */
    GAMEBIT_VFP_SeqBit1A0CF3 = 0xCF3,                    /* Named from map data alone - nothing in the code or in any name list mentions it: temple/VFP_Bobbing objId= param=bit1A; table 0 */
    GAMEBIT_VFP_SeqBit180CF4 = 0xCF4,                    /* Named from map data alone - nothing in the code or in any name list mentions it: temple/VFPSeqObj objId= param=bit18; table 2 */
    GAMEBIT_VFP_SeqBit180CF5 = 0xCF5,                    /* Named from map data alone - nothing in the code or in any name list mentions it: temple/CAMERAseqob objId= param=bit18; table 2 */
    GAMEBIT_VFP_Param200CF6 = 0xCF6,                     /* Named from map data alone - nothing in the code or in any name list mentions it: temple/VFP_seqpoin objId= param=_20; table 2 */
    GAMEBIT_VFP_SeqBit180CF7 = 0xCF7,                    /* Named from map data alone - nothing in the code or in any name list mentions it: temple/CAMERAseqob objId= param=bit18; table 2 */
    GAMEBIT_VFP_ClawAliveCF8 = 0xCF8,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_ClawAliveCF9 = 0xCF9,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_ClawAliveCFA = 0xCFA,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_QuadLatch0CFB = 0xCFB,                   /* Latched by VFP_LevelCo once all four of GAMEBIT_VFP_QuadPrereq0D6D through ...0D70 are up; Rena has it as temple HitAnimator 0x4C6F4's target */
    GAMEBIT_VFP_ClawDeadCFC = 0xCFC,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_ClawDeadCFD = 0xCFD,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_ClawDeadCFE = 0xCFE,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_Param1E0CFF = 0xCFF,                     /* Named from map data alone - nothing in the code or in any name list mentions it: temple/VFP_seqpoin objId= param=_1E; table 2 */
    GAMEBIT_NoBallsAllowed = 0xD00,                      /* table 3; Disables/despawns Tricky's ball */
    GAMEBIT_VFP_Activate0D01 = 0xD01,                    /* Named from map data alone - nothing in the code or in any name list mentions it: temple/TrigPln objId= param=activate; table 2 */
    GAMEBIT_VFP_HitAnimTarget0D02 = 0xD02,               /* Named from map data alone - nothing in the code or in any name list mentions it: temple/HitAnimator objId= param=target; temple/CAMERAseqob objId= param=bit1A; temple/TrigBits objId= param=activate; table 2 */
    GAMEBIT_SHBOT_SeqUsed0D04 = 0xD04,                   /* Named from map data alone - nothing in the code or in any name list mentions it: hollow2/SH_BottomSe objId= param=usedBit; table 2 */
    GAMEBIT_SHBOT_SeqNeed0D05 = 0xD05,                   /* Named from map data alone - nothing in the code or in any name list mentions it: hollow2/SH_BottomSe objId= param=needBit; table 2 */
    GAMEBIT_SH_EnteredWell = 0xD06,                      /* table 2; hint 271 */
    GAMEBIT_DIM_ClawDeadD07 = 0xD07,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_DIM_ClawDeadD08 = 0xD08,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_DIM_HitAnimTarget0D09 = 0xD09,               /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/HitAnimator objId= param=target; table 2 */
    GAMEBIT_DIM_HitAnimTarget0D0A = 0xD0A,               /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/HitAnimator objId= param=target; table 2 */
    GAMEBIT_DIM_LevelControlD0B = 0xD0B,                 /* The DLL names this one itself: DIM_LEVEL_CONTROL_GAMEBIT_D0B in DIM_LevelCo.c */
    GAMEBIT_DIM_LevelControlD0C = 0xD0C,                 /* The DLL names this one itself: DIM_LEVEL_CONTROL_GAMEBIT_D0C in DIM_LevelCo.c */
    GAMEBIT_DIM_LevelControlD0D = 0xD0D,                 /* The DLL names this one itself: DIM_LEVEL_CONTROL_GAMEBIT_D0D in DIM_LevelCo.c */
    GAMEBIT_DIM_LevelControlD0E = 0xD0E,                 /* The DLL names this one itself: DIM_LEVEL_CONTROL_GAMEBIT_D0E in DIM_LevelCo.c */
    GAMEBIT_NW_ClawDeadD0F = 0xD0F,                      /* Rena's U0 dataset; table 2 */
    GAMEBIT_NW_ClawDeadD10 = 0xD10,                      /* Rena's U0 dataset; table 2 */
    GAMEBIT_NW_TrickySharpClawDefeated = 0xD11,          /* consumed by NW_tricky: when set, the SnowHorn Wastes SharpClaws stop chasing Tricky and the controller advances to the command-learning phase */
    GAMEBIT_DIM_HitAnimTarget0D12 = 0xD12,               /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/HitAnimator objId= param=target; snowmines/DIMWoodDoor objId= param=open; snowmines/TrigBits objId= param=activate (+2 more); table 2 */
    GAMEBIT_DIM_SeqBit180D13 = 0xD13,                    /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/CAMERAseqob objId= param=bit18; table 2 */
    GAMEBIT_DIM_HitAnimTarget0D14 = 0xD14,               /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/HitAnimator objId= param=target; table 2 */
    GAMEBIT_NW_Key_Used = 0xD16,                         /* table 2; ref wastes/HitAnimator target. Backs the collectable item C-menu entry the game labels "Use Gate Key" (its used bit) */
    GAMEBIT_NW_PortcullClosedLatch0D17 = 0xD17,          /* Read out of the retail placement data: wastes/NW_Portcull closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_NW_FuelCellsVisibleD18 = 0xD18,              /* Rena's U0 dataset; table 2 */
    GAMEBIT_WM_HitAnimTarget0D19 = 0xD19,                /* Named from map data alone - nothing in the code or in any name list mentions it: warlock/HitAnimator objId= param=target; warlock/CCclawOnlyD objId= param=open; table 1 */
    GAMEBIT_NW_SeqBit180D1A = 0xD1A,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wastes/CAMERAseqob objId= param=bit18; table 2 */
    GAMEBIT_WM_SeqPointSpirit1 = 0xD1B,                  /* WMseqpoint calls it its spirit-1 bit; Rena had it only as WMRelated0D1B */
    GAMEBIT_WMRelated0D1C = 0xD1C,                       /* table 1 */
    GAMEBIT_WMRelated0D1D = 0xD1D,                       /* table 1 */
    GAMEBIT_WMRelated0D1E = 0xD1E,                       /* table 1 */
    GAMEBIT_WMRelated0D1F = 0xD1F,                       /* table 1 */
    GAMEBIT_NW_Key_Got = 0xD20,                          /* table 2; hint 275; XXX which? hint is "Saved Queen EarthWalker". Backs the collectable item C-menu entry the game labels "Use Gate Key" (its owned bit) */
    GAMEBIT_SHOP_Unk0D21 = 0xD21,                        /* table 0; set when entering shop */
    GAMEBIT_DIM2_HitAnimTarget0D22 = 0xD22,              /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines2/HitAnimator objId= param=target; table 2 */
    GAMEBIT_CF_SeqBit180D26 = 0xD26,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CAMERAseqob objId= param=bit18; table 2 */
    GAMEBIT_WM_KrystalCrystalized = 0xD27,               /* table 1 */
    GAMEBIT_FireflyFirstTouch = 0xD28,                   /* The DLL names this one itself: FIREFLY_FIRST_TOUCH_BIT in FireFly.c */
    GAMEBIT_MMP_MagicCave_Visible = 0xD29,               /* Rena's U0 dataset; table 2 */
    GAMEBIT_SawStaffBoostPad = 0xD2A,                    /* table 2; StaffActivated checks for this (hardcoded) in some case relating to sequences */
    GAMEBIT_SHBOT_StaffBoostEnabled = 0xD2B,             /* Rena's U0 dataset; table 2 */
    GAMEBIT_LINKC_Open0D2E = 0xD2E,                      /* Named from map data alone - nothing in the code or in any name list mentions it: linkc/LINK_Portcu objId= param=open; table 2 */
    GAMEBIT_LINKC_LINKPortcuClosedLatch0D2F = 0xD2F,     /* Read out of the retail placement data: linkc/LINK_Portcu closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DFSH_SeqBit1A0D30 = 0xD30,                   /* Named from map data alone - nothing in the code or in any name list mentions it: dfshrine/CAMERAseqob objId= param=bit1A; dfshrine/HitAnimator objId= param=target; table 0 */
    GAMEBIT_DFSH_SeqBit180D31 = 0xD31,                   /* Named from map data alone - nothing in the code or in any name list mentions it: dfshrine/CAMERAseqob objId= param=bit18; table 0 */
    GAMEBIT_NW_GateKeeperAirMeterActive = 0xD32,         /* SnowHorn Gate Keeper tumbleweed-rescue air-meter phase is active; set when the gatekeeper enlists Tricky/tumbleweed help, cleared when the air meter completes */
    GAMEBIT_NW_SeqUsed0D33 = 0xD33,                      /* Named from map data alone - nothing in the code or in any name list mentions it: wastes/NW_seqobjec objId= param=usedBit; table 2 */
    GAMEBIT_SH_Related0D35 = 0xD35,                      /* table 3 */
    GAMEBIT_SH_Related0D36 = 0xD36,                      /* table 3 */
    GAMEBIT_WM_FlewTo = 0xD37,                           /* table 1; hint 419; ref warlock/HitAnimator target */
    GAMEBIT_LINKF_ObjGroups = 0xD38,                     /* table 3; size 32 */
    GAMEBIT_SH_BloopEventDone = 0xD39,                   /* table 2 */
    GAMEBIT_CFRestartPointRelated0D3D = 0xD3D,           /* table 1 */
    GAMEBIT_VFP_HitAnimTarget0D3E = 0xD3E,               /* Named from map data alone - nothing in the code or in any name list mentions it: temple/HitAnimator objId= param=target; temple/VFPSeqObj objId= param=bit18; table 2 */
    GAMEBIT_VFP_DoorlocClosedLatch0D41 = 0xD41,          /* Read out of the retail placement data: temple/VFP_Doorloc closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_VFPLightRelated0D44 = 0xD44,                 /* table 3; ref temple/LGTDirectio 0x1E */
    GAMEBIT_MMP_HitAnimTarget0D45 = 0xD45,               /* Named from map data alone - nothing in the code or in any name list mentions it: moonpass/HitAnimator objId= param=target; moonpass/MMP_MagicCa objId= param=open; table 2 */
    GAMEBIT_MMP_MagicCaClosedLatch0D46 = 0xD46,          /* Read out of the retail placement data: moonpass/MMP_MagicCa closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_LevelControlEnvironmentA = 0xD47,        /* The DLL names this one itself: MMP_LEVEL_CONTROL_GAMEBIT_ENVIRONMENT_A in MMP_levelco.c */
    GAMEBIT_MoonSeedSpot10Harvested = 0xD4B,             /* One of the eleven moon-seed planting spots MSPlantingS maps from its placement ident: spot 10, ident 0x4B26E, whose map Rena does not record. This is its harvested bit, raised once the grown plant is cut and taken */
    GAMEBIT_MoonSeedSpot10Planted = 0xD4D,               /* One of the eleven moon-seed planting spots MSPlantingS maps from its placement ident: spot 10, ident 0x4B26E, whose map Rena does not record. This is its planted bit; planting also decrements the shared GAMEBIT_ITEM_MoonSeed_Count */
    GAMEBIT_DBSH_HitAnimTarget0D4E = 0xD4E,              /* Named from map data alone - nothing in the code or in any name list mentions it: dbshrine/HitAnimator objId= param=target; dbshrine/ExplodeWall objId= param=exploded; table 0 */
    GAMEBIT_DBSH_OnExplode0D4F = 0xD4F,                  /* Named from map data alone - nothing in the code or in any name list mentions it: dbshrine/ExplodeWall objId= param=onExplode; table 0 */
    GAMEBIT_MMP_AsteroidForceIntensity = 0xD52,          /* Pins the Moon Mountain Pass asteroid's intensity at 1 regardless of GAMEBIT_MMP_MoonRockPedestalCount; Rena has it as moonpass HitAnimator 0x4B451's target */
    GAMEBIT_WarpPointRelatedD53 = 0xD53,                 /* table 1 */
    GAMEBIT_MMP_FogControlEnable0D54 = 0xD54,            /* Read out of the retail placement data: moonpass/fogControl enableGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MMP_FogControlEnable0D55 = 0xD55,            /* Read out of the retail placement data: moonpass/fogControl enableGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_OFT_ClawAliveD56 = 0xD56,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_DFP_LevelControlSfxTriggerD59 = 0xD59,       /* The DLL names this one itself: DFP_LEVEL_CONTROL_SFX_TRIGGER_D59 in DFP_LevelCo.c */
    GAMEBIT_DFP_LevelControlSfxTriggerD5A = 0xD5A,       /* The DLL names this one itself: DFP_LEVEL_CONTROL_SFX_TRIGGER_D5A in DFP_LevelCo.c */
    GAMEBIT_OFT_SeqBit180D5B = 0xD5B,                    /* Named from map data alone - nothing in the code or in any name list mentions it: dfptop/CAMERAseqob objId= param=bit18; table 2 */
    GAMEBIT_OFT_SeqBit180D5C = 0xD5C,                    /* Named from map data alone - nothing in the code or in any name list mentions it: dfptop/CAMERAseqob objId= param=bit18; table 2 */
    GAMEBIT_DFP_LevelControlSfxTriggerD5D = 0xD5D,       /* The DLL names this one itself: DFP_LEVEL_CONTROL_SFX_TRIGGER_D5D in DFP_LevelCo.c */
    GAMEBIT_OFT_SeqBit180D5E = 0xD5E,                    /* Named from map data alone - nothing in the code or in any name list mentions it: dfptop/CAMERAseqob objId= param=bit18; table 2 */
    GAMEBIT_CF_SeqD65 = 0xD65,                           /* Rena's U0 dataset; table 0 */
    GAMEBIT_CR_RaceRelatedD66 = 0xD66,                   /* Rena's U0 dataset; table 0 */
    GAMEBIT_OFP_Entered = 0xD67,                         /* table 2; hint 339; ref dfptop/HitAnimator target */
    GAMEBIT_OFT_HitAnimTarget0D68 = 0xD68,               /* Named from map data alone - nothing in the code or in any name list mentions it: dfptop/HitAnimator objId= param=target; table 2 */
    GAMEBIT_VFP_Opened = 0xD69,                          /* table 2; hint 303 */
    GAMEBIT_VFP_Param200D6A = 0xD6A,                     /* Named from map data alone - nothing in the code or in any name list mentions it: temple/VFP_seqpoin objId= param=_20; table 2 */
    GAMEBIT_OFPTOP_WarpEnabled = 0xD6C,                  /* table 2; hint 340; ref dfptop/Transporter enabled */
    GAMEBIT_VFP_QuadPrereq0D6D = 0xD6D,                  /* First of the four bits GAMEBIT_VFP_QuadLatch0CFB waits on */
    GAMEBIT_VFP_QuadPrereq0D6E = 0xD6E,                  /* Second of GAMEBIT_VFP_QuadLatch0CFB's four */
    GAMEBIT_VFP_QuadPrereq0D6F = 0xD6F,                  /* Third of GAMEBIT_VFP_QuadLatch0CFB's four */
    GAMEBIT_VFP_QuadPrereq0D70 = 0xD70,                  /* Fourth of GAMEBIT_VFP_QuadLatch0CFB's four */
    GAMEBIT_VFP_SkyPending = 0xD72,                      /* The VFP DLL that uses it calls it sky-pending; Rena had it only as VFPRelated0D72 */
    GAMEBIT_CloudRaceResetBit0D73 = 0xD73,               /* One of the bits CRCloudRace clears as it resets the CloudRunner race; Rena's U0 dataset spells it CFRelated0D73, which carries no reading of its own */
    GAMEBIT_LINKH_ObjGroups = 0xD75,                     /* table 3; size 32 */
    GAMEBIT_DrakorCrateBroken0D76 = 0xD76,               /* Read out of the retail placement data: finalboss/DrakorCrate brokenGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DrakorCrateBroken0D77 = 0xD77,               /* Read out of the retail placement data: finalboss/DrakorCrate brokenGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DrakorCrateBroken0D78 = 0xD78,               /* Read out of the retail placement data: finalboss/DrakorCrate brokenGameBit x2; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DrakorCrateBroken0D79 = 0xD79,               /* Read out of the retail placement data: finalboss/DrakorCrate brokenGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DrakorCrateBroken0D7A = 0xD7A,               /* Read out of the retail placement data: finalboss/DrakorCrate brokenGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DrakorCrateBroken0D7B = 0xD7B,               /* Read out of the retail placement data: finalboss/DrakorCrate brokenGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_WC_MagicCaveVisible = 0xD7D,                 /* table 2; ref wallcity/MagicCaveTo Visible */
    GAMEBIT_WC_BombPlantedD7E = 0xD7E,                   /* Rena's U0 dataset; table 2 */
    GAMEBIT_WC_XYZAnimatorCompletion0D7F = 0xD7F,        /* Read out of the retail placement data: wallcity/XYZAnimator completionGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_WC_BurnableVinBurnedBit0D80 = 0xD80,         /* Read out of the retail placement data through FlammableVinePlacement.burnedBit: wallcity/BurnableVin x1; 1 placement. The struct is bound by the declared type of the variable the DLL reads the bit from, not guessed from what the DLL mentions */
    GAMEBIT_WC_SeqUsed0D81 = 0xD81,                      /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/CAMERAnewse objId= param=usedBit; table 2 */
    GAMEBIT_WC_SeqUsed0D82 = 0xD82,                      /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/CAMERAnewse objId= param=usedBit; table 2 */
    GAMEBIT_NW_GotPastBribeClaw = 0xD83,                 /* table 2; hint 266 */
    GAMEBIT_WC_Activate0D84 = 0xD84,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/TrigPln objId= param=activate; table 1 */
    GAMEBIT_WC_Activate0D85 = 0xD85,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/TrigPln objId= param=activate; table 1 */
    GAMEBIT_WC_Activate0D86 = 0xD86,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/TrigPln objId= param=activate; table 1 */
    GAMEBIT_WC_Activate0D87 = 0xD87,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/TrigPln objId= param=activate; table 1 */
    GAMEBIT_WC_Activate0D88 = 0xD88,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/TrigPln objId= param=activate; table 1 */
    GAMEBIT_WC_Activate0D89 = 0xD89,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/TrigPln objId= param=activate; table 1 */
    GAMEBIT_WC_Activate0D8A = 0xD8A,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/TrigPln objId= param=activate; table 1 */
    GAMEBIT_WC_Activate0D8B = 0xD8B,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/TrigPln objId= param=activate; table 1 */
    GAMEBIT_WC_SeqBit1A0D8C = 0xD8C,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit1A; table 2 */
    GAMEBIT_WC_SeqBit1A0D8D = 0xD8D,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit1A; table 2 */
    GAMEBIT_WC_SeqBit1A0D8E = 0xD8E,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit1A; table 2 */
    GAMEBIT_DIM_MusicLatch0D8F = 0xD8F,                  /* DIM_LevelCo's latch condition for its 0xDC track, the one of the four with no clear-bits at all; cleared by DIMboss_free on teardown */
    GAMEBIT_WC_SeqBit1A0D90 = 0xD90,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit1A; table 2 */
    GAMEBIT_WC_SeqBit180D91 = 0xD91,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit18; table 2 */
    GAMEBIT_WC_SeqBit180D92 = 0xD92,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit18; table 2 */
    GAMEBIT_WC_SeqBit180D93 = 0xD93,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit18; table 2 */
    GAMEBIT_WC_SeqBit180D94 = 0xD94,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit18; table 2 */
    GAMEBIT_WC_SeqBit180D95 = 0xD95,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit18; table 2 */
    GAMEBIT_WC_SeqBit1A0D96 = 0xD96,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit1A; table 2 */
    GAMEBIT_ITEM_FuelCell_ShowCount = 0xD97,             /* table 2; on HUD */
    GAMEBIT_WC_SHPortcullOpen0D98 = 0xD98,               /* Read out of the retail placement data: wallcity/SH_Portcull open x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM2_LavaControl0D99 = 0xD99,                /* The DLL names this one itself: DIM2_LAVA_CONTROL_GAMEBIT_0D99 in DIM2LavaCon.c */
    GAMEBIT_DIM_MaybeEnabled0D9A = 0xD9A,                /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/VFP_flamepo objId= param=maybeEnabled; snowmines/VFP_flamepo objId= param=maybeEnabled; snowmines/VFP_flamepo objId= param=maybeEnabled (+6 more); table 0 */
    GAMEBIT_DIM_WoodDoorClosedLatch0D9B = 0xD9B,         /* Read out of the retail placement data: snowmines/DIMWoodDoor closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM_WoodDoorClosedLatch0D9C = 0xD9C,         /* Read out of the retail placement data: snowmines/DIMWoodDoor closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM_WoodDoorClosedLatch0D9D = 0xD9D,         /* Read out of the retail placement data: snowmines/DIMWoodDoor closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM_WoodDoorClosedLatch0D9E = 0xD9E,         /* Read out of the retail placement data: snowmines/DIMWoodDoor closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_WC_Exists0DA1 = 0xDA1,                       /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/BombPlant objId= param=exists; table 2 */
    GAMEBIT_WC_HitAnimTarget0DA2 = 0xDA2,                /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/HitAnimator objId= param=target; table 2 */
    GAMEBIT_WC_Exists0DA3 = 0xDA3,                       /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/BombPlant objId= param=exists; table 2 */
    GAMEBIT_WC_HitAnimTarget0DA4 = 0xDA4,                /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/HitAnimator objId= param=target; table 2 */
    GAMEBIT_DIM2_AreaMusicActive = 0xDA5,                /* The DLL names this one itself: DIM2_GAMEBIT_AREA_MUSIC_ACTIVE in 478_DIM2LavaCon.h */
    GAMEBIT_CF_FogControlEnable0DA6 = 0xDA6,             /* Read out of the retail placement data: fortress/fogControl enableGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM_HitAnimTarget0DA7 = 0xDA7,               /* Named from map data alone - nothing in the code or in any name list mentions it: snowmines/HitAnimator objId= param=target; table 2 */
    GAMEBIT_WC_StopwatchEnabled = 0xDA9,                 /* Walled City countdown stopwatch enabled - Rena has it driving wallcity's CNTstopwatc 'enabled' param; wclevelcont treats it, or gameTimerIsRunning, as 'a countdown is up' while the push-block timer is off, and clears it when the final sequence completes */
    GAMEBIT_CF_SCShrinedClosedLatch0DAA = 0xDAA,         /* Read out of the retail placement data: fortress/SC_Shrine_d closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIMLightRelatedDAB = 0xDAB,                  /* Rena's U0 dataset; table 3 */
    GAMEBIT_CC_Currents2_Disable = 0xDB5,                /* Disables more water currents in Cape Claw when some switch is activated; Rena's U0 dataset; table 2 */
    GAMEBIT_CC_HitAnimTarget0DB6 = 0xDB6,                /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/HitAnimator objId= param=target; capeclaw/ExplodeWall objId= param=exploded; table 2 */
    GAMEBIT_CC_HitAnimTarget0DB7 = 0xDB7,                /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/HitAnimator objId= param=target; capeclaw/ExplodeWall objId= param=exploded; capeclaw/HitAnimator objId= param=target; table 2 */
    GAMEBIT_CloudRaceResetBit0DB8 = 0xDB8,               /* One of the bits CRCloudRace clears as it resets the CloudRunner race; Rena's U0 dataset spells it CFRelated0DB8, which carries no reading of its own */
    GAMEBIT_DIMLightRelatedDBA = 0xDBA,                  /* Rena's U0 dataset; table 3 */
    GAMEBIT_CC_OnExplode0DBB = 0xDBB,                    /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/ExplodeWall objId= param=onExplode; table 2 */
    GAMEBIT_CC_OnExplode0DBC = 0xDBC,                    /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/ExplodeWall objId= param=onExplode; table 2 */
    GAMEBIT_MMP_ClawDeadD8D = 0xDBD,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_MMP_ClawDeadD8E = 0xDBE,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_OpenedPathTo = 0xDBF,                    /* table 2; hint 300; ref moonpass/HitAnimator target */
    GAMEBIT_CC_HitAnimTarget0DC0 = 0xDC0,                /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/HitAnimator objId= param=target; capeclaw/CCseqobj objId= param=needBit; table 2 */
    GAMEBIT_CC_SeqUsed0DC1 = 0xDC1,                      /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/CCseqobj objId= param=usedBit; table 2 */
    GAMEBIT_CC_HitAnimTarget0DC3 = 0xDC3,                /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/HitAnimator objId= param=target; table 3 */
    GAMEBIT_MMP_SeqBit180DC4 = 0xDC4,                    /* Named from map data alone - nothing in the code or in any name list mentions it: moonpass/CAMERAseqob objId= param=bit18; table 2 */
    GAMEBIT_CC_Pedestal0DC5 = 0xDC5,                     /* The DLL names this one itself: CC_PEDESTAL_GAMEBIT_0DC5 in CCpedstal.c */
    GAMEBIT_CC_SeqUsed0DC6 = 0xDC6,                      /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/CAMERAnewse objId= param=usedBit; table 2 */
    GAMEBIT_MMP_MoonrocPickupGate0DC7 = 0xDC7,           /* Read out of the retail placement data: moonpass/MMP_moonroc pickupGateGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CloudRaceCompletionEvent = 0xDCA,            /* CRCloudRace calls it its completion event; Rena had it only as CFRelated0DCA */
    GAMEBIT_CloudRaceEffectClear = 0xDCB,                /* CRCloudRace calls it its effect-clear bit */
    GAMEBIT_OFP_MusicLatch = 0xDCE,                      /* Ocean Force Point level-controller music latch */
    GAMEBIT_VFP_MusicLatch = 0xDCF,                      /* Volcano Force Point level-controller music latch */
    GAMEBIT_CC_HitAnimTarget0DD0 = 0xDD0,                /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/HitAnimator objId= param=target; table 2 */
    GAMEBIT_LINKD_ObjGroups = 0xDD1,                     /* table 3; size 32 */
    GAMEBIT_GPSH_TestKnowledgeRunning = 0xDD2,           /* GPSH shrine (Test Of Knowledge) trial-active latch - set on activation, cleared on solve/timeout/reset; gates MUSICTRIG_krazoa_tunnel_2 via GameBitLatch_Update, mirroring GAMEBIT_ECSH_TestObservRunning */
    GAMEBIT_DBSH_ShrineApproach = 0xDD3,                 /* The DLL names this one itself: DBSH_SHRINE_GAMEBIT_APPROACH in DBSH_Shrine.c */
    GAMEBIT_CF_AreaFXEmitEnable0DD6 = 0xDD6,             /* Read out of the retail placement data: fortress/AreaFXEmit enableGameBit x1 */
    GAMEBIT_CC_HitAnimTarget0DD8 = 0xDD8,                /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/HitAnimator objId= param=target; table 2 */
    GAMEBIT_SC_BurnableVinBurnedBit0DD9 = 0xDD9,         /* Read out of the retail placement data through FlammableVinePlacement.burnedBit: swapcircle/BurnableVin x1; 1 placement. The struct is bound by the declared type of the variable the DLL reads the bit from, not guessed from what the DLL mentions */
    GAMEBIT_CC_FuelCellVisible_DDA = 0xDDA,              /* Rena's U0 dataset; table 2 */
    GAMEBIT_ITEM_CheatToken0_Got = 0xDDC,                /* table 2; Display Credits. Backs the collectable item C-menu entry the game labels "Drop Token" (its owned bit) */
    GAMEBIT_ITEM_CheatToken3_Got = 0xDDD,                /* table 2; Dino Language. Backs the collectable item C-menu entry the game labels "Drop Token" (its owned bit) */
    GAMEBIT_ITEM_CheatToken2_Got = 0xDDE,                /* table 2; Music Test. Backs the collectable item C-menu entry the game labels "Drop Token" (its owned bit) */
    GAMEBIT_ITEM_CheatToken6_Got = 0xDDF,                /* table 2. Backs the collectable item C-menu entry the game labels "Drop Token" (its owned bit) */
    GAMEBIT_ITEM_CheatToken4_Got = 0xDE0,                /* table 2. Backs the collectable item C-menu entry the game labels "Drop Token" (its owned bit) */
    GAMEBIT_ITEM_CheatToken7_Got = 0xDE1,                /* table 2. Backs the collectable item C-menu entry the game labels "Drop Token" (its owned bit) */
    GAMEBIT_ITEM_CheatToken1_Got = 0xDE2,                /* table 2; Sepia Mode. Backs the collectable item C-menu entry the game labels "Drop Token" (its owned bit) */
    GAMEBIT_ITEM_CheatToken5_Got = 0xDE3,                /* table 2. Backs the collectable item C-menu entry the game labels "Drop Token" (its owned bit) */
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
    GAMEBIT_OFB_Open0DEE = 0xDEE,                        /* Named from map data alone - nothing in the code or in any name list mentions it: kraztest/OFPclawOnly objId= param=open; kraztest/CAMERAseqob objId= param=bit1A; table 2 */
    GAMEBIT_OFB_SeqBit180DEF = 0xDEF,                    /* Named from map data alone - nothing in the code or in any name list mentions it: kraztest/CAMERAseqob objId= param=bit18; table 2 */
    GAMEBIT_CC_Pedestal0DF0 = 0xDF0,                     /* The DLL names this one itself: CC_PEDESTAL_GAMEBIT_0DF0 in CCpedstal.c */
    GAMEBIT_CC_HitAnimTarget0DF1 = 0xDF1,                /* Named from map data alone - nothing in the code or in any name list mentions it: capeclaw/HitAnimator objId= param=target; table 2 */
    GAMEBIT_OFB_ClawDeadDF4 = 0xDF4,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_OFB_ClawDeadDF5 = 0xDF5,                     /* also affects some light in DIM2; Rena's U0 dataset; table 2 */
    GAMEBIT_CreditsRelated0DF6 = 0xDF6,                  /* table 0; Set on title screen when showing credits (maybe "should run credits"?) */
    GAMEBIT_DIM2_LightRelatedDF8 = 0xDF8,                /* Rena's U0 dataset; table 2 */
    GAMEBIT_LINKF_Open0DF9 = 0xDF9,                      /* Named from map data alone - nothing in the code or in any name list mentions it: linkf/LINK_Portcu objId= param=open; linkf/HitAnimator objId= param=target; table 2 */
    GAMEBIT_LINKF_Open0DFA = 0xDFA,                      /* Named from map data alone - nothing in the code or in any name list mentions it: linkf/LINK_Portcu objId= param=open; linkf/HitAnimator objId= param=target; table 2 */
    GAMEBIT_LINKF_Open0DFB = 0xDFB,                      /* Named from map data alone - nothing in the code or in any name list mentions it: linkf/LINK_Portcu objId= param=open; linkf/HitAnimator objId= param=target; linkf/StaffLeverO objId= param=activated; table 2 */
    GAMEBIT_LINKF_LINKPortcuClosedLatch0DFC = 0xDFC,     /* Read out of the retail placement data: linkf/LINK_Portcu closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_LINKF_LINKPortcuClosedLatch0DFD = 0xDFD,     /* Read out of the retail placement data: linkf/LINK_Portcu closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_LINKF_LINKPortcuClosedLatch0DFE = 0xDFE,     /* Read out of the retail placement data: linkf/LINK_Portcu closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SH_PushedSwitchInWell = 0xDFF,               /* table 2 */
    GAMEBIT_CC_GotPastGuardClaw = 0xE00,                 /* Rena's U0 dataset; table 2 */
    GAMEBIT_OFB_SeqBit180E01 = 0xE01,                    /* Named from map data alone - nothing in the code or in any name list mentions it: kraztest/CAMERAseqob objId= param=bit18; table 2 */
    GAMEBIT_OFB_SeqBit180E02 = 0xE02,                    /* Named from map data alone - nothing in the code or in any name list mentions it: kraztest/CAMERAseqob objId= param=bit18; table 2 */
    GAMEBIT_OFB_Open0E03 = 0xE03,                        /* Named from map data alone - nothing in the code or in any name list mentions it: kraztest/OFPclawOnly objId= param=open; kraztest/CAMERAseqob objId= param=bit1A; table 2 */
    GAMEBIT_OFB_SeqBit180E04 = 0xE04,                    /* Named from map data alone - nothing in the code or in any name list mentions it: kraztest/CAMERAseqob objId= param=bit18; table 2 */
    GAMEBIT_WC_MagicCaveRelated0E05 = 0xE05,             /* table 2; cleared when Arwing flies to Walled City */
    GAMEBIT_MMP_WallExplodedE08 = 0xE08,                 /* Rena's U0 dataset; table 2 */
    GAMEBIT_MMP_WallExplodingE09 = 0xE09,                /* Rena's U0 dataset; table 2 */
    GAMEBIT_MMP_BombPlantedE0A = 0xE0A,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_VFP_MSBushGrowthTrigger0E0C = 0xE0C,         /* Read out of the retail placement data: temple/MSBush growthTriggerGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_VFP_MSBushPlanted0E0D = 0xE0D,               /* Read out of the retail placement data: temple/MSBush plantedGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_VFP_MSVineGrowthTrigger0E0E = 0xE0E,         /* Read out of the retail placement data: temple/MSVine growthTriggerGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_VFP_MSVinePlanted0E0F = 0xE0F,               /* Read out of the retail placement data: temple/MSVine plantedGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_MoonSeedSpot11Harvested = 0xE10,             /* One of the eleven moon-seed planting spots MSPlantingS maps from its placement ident: spot 11, ident 0x4BEA3, which Rena places in temple. This is its harvested bit, raised once the grown plant is cut and taken */
    GAMEBIT_VFP_SeqBit180E11 = 0xE11,                    /* Named from map data alone - nothing in the code or in any name list mentions it: temple/MSSeqObject objId= param=bit18; temple/HitAnimator objId= param=target; table 2 */
    GAMEBIT_VFP_SeqUsed0E16 = 0xE16,                     /* Named from map data alone - nothing in the code or in any name list mentions it: temple/CAMERAnewse objId= param=usedBit; table 2 */
    GAMEBIT_VFP_SeqStep2 = 0xE17,                        /* The DLL names this one itself: GAMEBIT_VFP_SEQ_STEP_2 in VFP_LevelCo.c */
    GAMEBIT_VFP_SeqStep3 = 0xE18,                        /* The DLL names this one itself: GAMEBIT_VFP_SEQ_STEP_3 in VFP_LevelCo.c */
    GAMEBIT_VFP_SeqStep1 = 0xE19,                        /* The DLL names this one itself: GAMEBIT_VFP_SEQ_STEP_1 in VFP_LevelCo.c */
    GAMEBIT_VFP_SeqStep0 = 0xE1A,                        /* The DLL names this one itself: GAMEBIT_VFP_SEQ_STEP_0 in VFP_LevelCo.c */
    GAMEBIT_VFP_SeqNeed0E1B = 0xE1B,                     /* Named from map data alone - nothing in the code or in any name list mentions it: temple/CAMERAnewse objId= param=needBit; temple/HitAnimator objId= param=target; table 2 */
    GAMEBIT_VFP_SeqUsed0E1C = 0xE1C,                     /* Named from map data alone - nothing in the code or in any name list mentions it: temple/CAMERAnewse objId= param=usedBit; table 2 */
    GAMEBIT_CloudRaceResetBit0E1D = 0xE1D,               /* One of the bits CRCloudRace clears as it resets the CloudRunner race; Rena's U0 dataset spells it CFRelated0E1D, which carries no reading of its own */
    GAMEBIT_WarpActive0E1E = 0xE1E,                      /* Another warp-in-progress bit - SC_levelcon makes it the GameBitLatch condition their level controllers attach to MUSICTRIG_Teleport (0x36, track 85 SNGTeleport), and LINK_levcon stops choosing ambient music for its area while it is set, which is what that DLL's local enum was reading as an area disable */
    GAMEBIT_VFP_Enabled0E1F = 0xE1F,                     /* Named from map data alone - nothing in the code or in any name list mentions it: temple/StaffLeverO objId= param=enabled; table 2 */
    GAMEBIT_MoonSeedSpot11Planted = 0xE21,               /* One of the eleven moon-seed planting spots MSPlantingS maps from its placement ident: spot 11, ident 0x4BEA3, which Rena places in temple. This is its planted bit; planting also decrements the shared GAMEBIT_ITEM_MoonSeed_Count */
    GAMEBIT_VFP_SeqBit180E22 = 0xE22,                    /* Named from map data alone - nothing in the code or in any name list mentions it: temple/VFPSeqObj objId= param=bit18; table 2 */
    GAMEBIT_CloudRaceResetBit0E23 = 0xE23,               /* One of the bits CRCloudRace clears as it resets the CloudRunner race; Rena's U0 dataset spells it CFRelated0E23, which carries no reading of its own */
    GAMEBIT_CloudRaceStartLatchA = 0xE24,                /* The DLL names this one itself: CRCLOUDRACE_GAMEBIT_START_LATCH_A in crcloudrace.h */
    GAMEBIT_OpenedSecondPathThroughTemple = 0xE25,       /* table 2; hint 371; ref temple/HitAnimator target */
    GAMEBIT_DR_Unk0E26 = 0xE26,                          /* table 3; toggled constantly in Dragon Rock */
    GAMEBIT_DR_RescuedEarthWalker = 0xE27,               /* table 2; hint 388 */
    GAMEBIT_DR_LeverActivated0E28 = 0xE28,               /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/StaffLeverO objId= param=activated; dragrock/CAMERAnewse objId= param=needBit; table 2 */
    GAMEBIT_DR_HitAnimTarget0E29 = 0xE29,                /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/HitAnimator objId= param=target; dragrock/StaffLeverO objId= param=activated; dragrock/DR_EarthDoo objId= param=open (+1 more); table 2 */
    GAMEBIT_DR_SeqUsed0E2A = 0xE2A,                      /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/CAMERAnewse objId= param=usedBit; table 2 */
    GAMEBIT_DR_RobotGenerator1Destroyed = 0xE30,         /* First of the four hidden Dragon Rock robot generators - Rena has each as a dragrock ExplodeWall 'exploded' plus a HitAnimator target, and GAMEBIT_DR_ShutDownRobotShields' own hint calls them the generators to search the level for; drmusiccont_update sets that bit and plays the completion jingle once all four are up, chiming progress on each change */
    GAMEBIT_DR_RobotGenerator2Destroyed = 0xE31,         /* Second Dragon Rock robot generator destroyed */
    GAMEBIT_DR_RobotGenerator3Destroyed = 0xE32,         /* Third Dragon Rock robot generator destroyed */
    GAMEBIT_DR_RobotGenerator4Destroyed = 0xE33,         /* Fourth Dragon Rock robot generator destroyed */
    GAMEBIT_LINKJ_BurnableVinBurnedBit0E34 = 0xE34,      /* Read out of the retail placement data through FlammableVinePlacement.burnedBit: linkj/BurnableVin x1; 1 placement. The struct is bound by the declared type of the variable the DLL reads the bit from, not guessed from what the DLL mentions */
    GAMEBIT_DR_SeqNeed0E35 = 0xE35,                      /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/CAMERAnewse objId= param=needBit; dragrock/SH_Portcull objId= param=open; table 2 */
    GAMEBIT_DR_SeqUsed0E36 = 0xE36,                      /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/CAMERAnewse objId= param=usedBit; table 2 */
    GAMEBIT_GPSH_TestKnowledgeFailed = 0xE37,            /* table 0; raised as the Test of Knowledge takes its fail transition, in the same breath as clearing GAMEBIT_GPSH_TestKnowledgeRunning, and cleared again by the reset block */
    GAMEBIT_DR_Robot1Destroyed = 0xE38,                  /* First of the four Dragon Rock robots taken down once their shields are off; drmusiccont_update chimes this quad exactly as it does the generators, and the four sit contiguously in save storage immediately before GAMEBIT_DR_DestroyedRobots - Rena records no map objref, so the per-robot pairing is from that adjacency and the shared chime logic */
    GAMEBIT_DR_RobotsDestroyedChimePlayed = 0xE39,       /* Latch stopping the all-four-robots jingle from replaying; drmusiccont only reads it, seeding its shadow copy at init and thereafter raising the shadow alone, so nothing in the DLL writes the bit back */
    GAMEBIT_GPSH_Related0E3A = 0xE3A,                    /* table 0; the Test of Knowledge shrine only ever clears it, in its reset block */
    GAMEBIT_LINKJ_SeqUsed0E3B = 0xE3B,                   /* Named from map data alone - nothing in the code or in any name list mentions it: linkj/LINKJseqobj objId= param=usedBit; table 2 */
    GAMEBIT_DR_Robot2Destroyed = 0xE3C,                  /* Second Dragon Rock robot destroyed */
    GAMEBIT_DR_Robot3Destroyed = 0xE3D,                  /* Third Dragon Rock robot destroyed */
    GAMEBIT_DR_Robot4Destroyed = 0xE3E,                  /* Fourth Dragon Rock robot destroyed */
    GAMEBIT_DR_DestroyedRobots = 0xE3F,                  /* table 2; hint 390 */
    GAMEBIT_DR_SeqUsed0E40 = 0xE40,                      /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/CAMERAnewse objId= param=usedBit; table 2 */
    GAMEBIT_CF_ClawAliveE41 = 0xE41,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_ClawAliveE42 = 0xE42,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_DR_VFPPuzzlePPressed0E43 = 0xE43,            /* Read out of the retail placement data: dragrock/VFP_PuzzleP pressedGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DR_VFPPuzzlePPressed0E44 = 0xE44,            /* Read out of the retail placement data: dragrock/VFP_PuzzleP pressedGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_LINKJ_SeqUsed0E48 = 0xE48,                   /* Named from map data alone - nothing in the code or in any name list mentions it: linkj/LINKJseqobj objId= param=usedBit; linkj/LINKJseqobj objId= param=usedBit; table 1 */
    GAMEBIT_WM_NewCrystalAmbientFx = 0xE49,              /* WMnewcrystal calls it its ambient-fx bit; Rena had it only as WM_KrystalRelated0E49 */
    GAMEBIT_DR_SeqUsed0E4A = 0xE4A,                      /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/CAMERAnewse objId= param=usedBit; table 2 */
    GAMEBIT_WM_VFPstatuebActivation0E4E = 0xE4E,         /* Read out of the retail placement data: warlock/VFP_statueb activationGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_WM_VFPstatuebActivation0E4F = 0xE4F,         /* Read out of the retail placement data: warlock/VFP_statueb activationGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_WM_DRLaserCanDestroyed0E50 = 0xE50,          /* Read out of the retail placement data: warlock/DR_LaserCan destroyedGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DBSH_Param240E51 = 0xE51,                    /* Named from map data alone - nothing in the code or in any name list mentions it: dbshrine/FireWorkSou objId= param=_24; dbshrine/FireWorkSou objId= param=_24; dbshrine/FireWorkSou objId= param=_24 (+4 more); table 0 */
    GAMEBIT_CC_ClawDeadE52 = 0xE52,                      /* Rena's U0 dataset; table 2 */
    GAMEBIT_WM_HitAnimTarget0E53 = 0xE53,                /* Named from map data alone - nothing in the code or in any name list mentions it: warlock/TrigCyl objId= param=activate; warlock/HitAnimator objId= param=target; warlock/HitAnimator objId= param=target; table 0 */
    GAMEBIT_WM_HitAnimTarget0E54 = 0xE54,                /* Named from map data alone - nothing in the code or in any name list mentions it: warlock/HitAnimator objId= param=target; table 1 */
    GAMEBIT_WM_SeqBit180E56 = 0xE56,                     /* Named from map data alone - nothing in the code or in any name list mentions it: warlock/CAMERAseqob objId= param=bit18; table 2 */
    GAMEBIT_OFP_ElectricFloorPuzzleAct1Complete = 0xE57, /* disables the act 1 electric-floor puzzle and lowers its floor bars */
    GAMEBIT_OFP_ElectricFloorPuzzleAct2Complete = 0xE58, /* disables the act 2 electric-floor puzzle and lowers its floor bars */
    GAMEBIT_OFT_LightRelatedE5A = 0xE5A,                 /* Rena's U0 dataset; table 1 */
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
    GAMEBIT_WC_SeqUsed0E6C = 0xE6C,                      /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/CAMERAnewse objId= param=usedBit; table 2 */
    GAMEBIT_WC_TrexLever2Enabled = 0xE6D,                /* Switches on the second T-rex lever - wallcity StaffLeverO 0x4CB3E's enabled param, the same object GAMEBIT_WC_TrexLever2Activated reports the pull of; wclevelcont clears it while arming a run */
    GAMEBIT_ProjectileSwitchParent0E6E = 0xE6E,          /* The gamebit a projectile switch inherits when its parent's placement ident is 0x31CE0, the second row of gProjectileSwitchParentGameBitMap; the first row hands out GAMEBIT_VFP_DragHeadSpawnBlocked */
    GAMEBIT_SH_ReturnedToWarpStone = 0xE6F,              /* table 0; hint 313; Fox returned with first spirit */
    GAMEBIT_MMP_EnteredKrazoaShrine = 0xE70,             /* table 0; hint 311 */
    GAMEBIT_WC_Enabled0E71 = 0xE71,                      /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/StaffLeverO objId= param=enabled; wallcity/HitAnimator objId= param=target; table 1 */
    GAMEBIT_WC_SeqUsed0E72 = 0xE72,                      /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/CAMERAnewse objId= param=usedBit; table 2 */
    GAMEBIT_WC_SeqUsed0E73 = 0xE73,                      /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/CAMERAnewse objId= param=usedBit; table 1 */
    GAMEBIT_ArwingRelated0E74 = 0xE74,                   /* table 0 */
    GAMEBIT_WM_Param200E78 = 0xE78,                      /* Named from map data alone - nothing in the code or in any name list mentions it: warlock/WM_seqpoint objId= param=_20; table 2 */
    GAMEBIT_WM_VortexRelatedE79 = 0xE79,                 /* Rena's U0 dataset; table 2 */
    GAMEBIT_DRArwingRelated0E7B = 0xE7B,                 /* table 2; cleared when Arwing flies to Dragon Rock */
    GAMEBIT_OFB_HitAnimTarget0E7C = 0xE7C,               /* Named from map data alone - nothing in the code or in any name list mentions it: kraztest/StaffLeverT objId= param=activated; kraztest/HitAnimator objId= param=target; kraztest/HitAnimator objId= param=target; table 2 */
    GAMEBIT_TTH_DustMoteE7D = 0xE7D,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_DR_LightRelatedE7F = 0xE7F,                  /* Rena's U0 dataset; table 3 */
    GAMEBIT_SH_EggEventRelated0E80 = 0xE80,              /* table 2 */
    GAMEBIT_MMSH_Shrine0E82 = 0xE82,                     /* The DLL names this one itself: MMSH_SHRINE_GAMEBIT_0E82 in MMSH_Shrine.c */
    GAMEBIT_MMSH_Shrine0E83 = 0xE83,                     /* The DLL names this one itself: MMSH_SHRINE_GAMEBIT_0E83 in MMSH_Shrine.c */
    GAMEBIT_MMSH_Shrine0E84 = 0xE84,                     /* The DLL names this one itself: MMSH_SHRINE_GAMEBIT_0E84 in MMSH_Shrine.c */
    GAMEBIT_MMSH_Shrine0E85 = 0xE85,                     /* The DLL names this one itself: MMSH_SHRINE_GAMEBIT_0E85 in MMSH_Shrine.c */
    GAMEBIT_SC_SeqBit1A0E86 = 0xE86,                     /* Named from map data alone - nothing in the code or in any name list mentions it: swapcircle/SC_sequence objId= param=bit1A; table 0 */
    GAMEBIT_SC_SeqBit180E87 = 0xE87,                     /* Named from map data alone - nothing in the code or in any name list mentions it: swapcircle/SC_sequence objId= param=bit18; table 2 */
    GAMEBIT_CF_SeqBit180E88 = 0xE88,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/CAMERAseqob objId= param=bit18; table 2 */
    GAMEBIT_CF_LandingPadE89 = 0xE89,                    /* Rena's U0 dataset; table 1 */
    GAMEBIT_CF_LargeCrateBroken0E8A = 0xE8A,             /* Read out of the retail placement data: fortress/LargeCrate brokenGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SC_SeqBit180E8F = 0xE8F,                     /* Named from map data alone - nothing in the code or in any name list mentions it: swapcircle/SC_sequence objId= param=bit18; table 2 */
    GAMEBIT_TestFearStaffBoostEnabled = 0xE91,           /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_Activate0E93 = 0xE93,                     /* Named from map data alone - nothing in the code or in any name list mentions it: fortress/TrigPln objId= param=activate; table 2 */
    GAMEBIT_LINKJ_SeqNeed0E95 = 0xE95,                   /* Named from map data alone - nothing in the code or in any name list mentions it: linkj/LINKJseqobj objId= param=needBit; linkj/LINKJseqobj objId= param=needBit; table 1 */
    GAMEBIT_ITEM_FuelCell_CantGet = 0xE97,               /* table 0; Used when currently collecting one */
    GAMEBIT_DR_WallExplodedE98 = 0xE98,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_DR_WallExplodedE99 = 0xE99,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_DR_WallExplodedE9A = 0xE9A,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_DR_WallExplodedE9B = 0xE9B,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_DR_ShutDownRobotShields = 0xE9C,             /* table 2; hint 389 */
    GAMEBIT_DIM_GroundAnimaSunk0E9D = 0xE9D,             /* Read out of the retail placement data: snowmines/GroundAnima sunkGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DIM_GroundAnimaSunk0E9E = 0xE9E,             /* Read out of the retail placement data: snowmines/GroundAnima sunkGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_WM_DestroyedBox5 = 0xE9F,                    /* table 2; second set */
    GAMEBIT_WM_DestroyedBox6 = 0xEA0,                    /* table 2 */
    GAMEBIT_WC_EnteredShrine = 0xEA1,                    /* table 0; hint 413 */
    GAMEBIT_K6_Entered = 0xEA2,                          /* table 0; hint 421 */
    GAMEBIT_DR_ChimneyReset0EA4 = 0xEA4,                 /* The DR chimney DLL calls it its reset bit, spelling the object DRCHIMMEY; DLL 620 raises it when its X falls outside the window that would instead have raised its placement's openedGameBit */
    GAMEBIT_OFPBOT_StaffBoostEnabled = 0xEA5,            /* table 2; ref kraztest/StaffBoostP enabled */
    GAMEBIT_ToldGetSnowHornArtifact = 0xEA6,             /* table 0 */
    GAMEBIT_NW_GateKeeperCommsPlayed = 0xEA7,            /* one-shot incoming-communication latch in the SnowHorn Gate Keeper post-rescue/default dialogue path */
    GAMEBIT_SH_Give200ScarabBag = 0xEA8,                 /* table 2; Triggers a respawn point save */
    GAMEBIT_SH_GiveMoonPassKey = 0xEA9,                  /* table 2; Triggers a respawn point save */
    GAMEBIT_DIM_LevelControl0EAD = 0xEAD,                /* The DLL names this one itself: DIM_LEVEL_CONTROL_GAMEBIT_0EAD in DIM_LevelCo.c */
    GAMEBIT_WM_SeqUsed0EAE = 0xEAE,                      /* Named from map data alone - nothing in the code or in any name list mentions it: warlock/CAMERAnewse objId= param=usedBit; table 2 */
    GAMEBIT_WM_SpiritPlaceShifted0EAF = 0xEAF,           /* One of three conditions - with GAMEBIT_WM_FoundKrystal and a map act above 2 - that shift the WM spirit placement 25 units along X */
    GAMEBIT_ITEM_BadGuyAlert_Got = 0xEB0,                /* table 2; unused shop item */
    GAMEBIT_ITEM_Magic_Got = 0xEB1,                      /* table 2 */
    GAMEBIT_ITEM_BafomdadHolder_Got = 0xEB2,             /* table 2 */
    GAMEBIT_SH_Related0EB3 = 0xEB3,                      /* table 2 */
    GAMEBIT_WM_SeqEB4 = 0xEB4,                           /* Rena's U0 dataset; table 2 */
    GAMEBIT_ITEM_Flute_Disabled = 0xEB5,                 /* table 2. Backs the collectable item C-menu entry the game labels "Blow Flute" (its active bit) */
    GAMEBIT_CF_KytesMumQuestStage1 = 0xEB9,              /* Written as a boolean of Kyte's mum's quest count being exactly 1, so it tracks her first quest stage; Rena has it as fortress HitAnimator 0x4CD31's target */
    GAMEBIT_OFB_DIMPushBlocBit0EBB = 0xEBB,              /* A DarkIce push-block's gamebit, from its placement's field at 0x18. That slot is corroborated rather than assumed: the Walled City push blocks are the same DLL and read the same offset, and the three ids they hold there are exactly GAMEBIT_WC_Switch1/2/3Activated, which were named from WCLevelCont's code. PushableObjectDef overruns the 0x24 record at its tail, but this field is inside it */
    GAMEBIT_OFB_DIMPushBlocBit0EBC = 0xEBC,              /* A DarkIce push-block's gamebit, from its placement's field at 0x18. That slot is corroborated rather than assumed: the Walled City push blocks are the same DLL and read the same offset, and the three ids they hold there are exactly GAMEBIT_WC_Switch1/2/3Activated, which were named from WCLevelCont's code. PushableObjectDef overruns the 0x24 record at its tail, but this field is inside it */
    GAMEBIT_ECSH_CameraLookingAtDoor = 0xECA,            /* table 2; focuses camera on door */
    GAMEBIT_NW_EscapedFromSnowClearing = 0xECC,          /* table 0; hint 265 */
    GAMEBIT_NW_WalkSequenceRunning = 0xECD,              /* table 0; raised as NW_levcontr starts its walk-table sequence off GAMEBIT_SnowHornArtifact19D, and cleared again by its cleanup mode */
    GAMEBIT_VFP_Entered = 0xECE,                         /* table 0; hint 301 */
    GAMEBIT_FoundSpellStoneWarpPad_0ECF = 0xECF,         /* table 0; hint 304 */
    GAMEBIT_OFP_FoundSpellStoneWarpPad = 0xED0,          /* table 0; hint 341 */
    GAMEBIT_DrakorCrateBroken0ED1 = 0xED1,               /* Read out of the retail placement data: finalboss/DrakorCrate brokenGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DrakorCrateBroken0ED2 = 0xED2,               /* Read out of the retail placement data: finalboss/DrakorCrate brokenGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DrakorCrateBroken0ED3 = 0xED3,               /* Read out of the retail placement data: finalboss/DrakorCrate brokenGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DrakorCrateBroken0ED4 = 0xED4,               /* Read out of the retail placement data: finalboss/DrakorCrate brokenGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DrakorCrateBroken0ED5 = 0xED5,               /* Read out of the retail placement data: finalboss/DrakorCrate brokenGameBit x1; wallcity/SH_Portcull open x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DR_OnCloudRunner = 0xED7,                    /* table 0 */
    GAMEBIT_OFB_FogControlEnable0ED8 = 0xED8,            /* Read out of the retail placement data: kraztest/fogControl enableGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_AreaFXEmitEnable0ED9 = 0xED9,                /* Read out of the retail placement data: finalboss/AreaFXEmit enableGameBit x1 */
    GAMEBIT_AreaFXEmitEnable0EDA = 0xEDA,                /* Read out of the retail placement data: finalboss/AreaFXEmit enableGameBit x1 */
    GAMEBIT_WC_TempleBridgeActive = 0xEDB,               /* Walled City temple bridge live - WCTempleBri raises it as the bridge solves and drops it when the bridge goes inactive or the player passes 1000 units away; KT_RexLevel_free also clears it so its arena leaves no stale global state */
    GAMEBIT_WC_TimedPuzzleBTimerActive = 0xEDC,          /* Walled City timed push-block puzzle B - countdown displayed; raised with GAMEBIT_WC_PushBlockTimerActive while B runs and cleared on solve, timeout or abort */
    GAMEBIT_WC_TimedPuzzleATimerActive = 0xEDD,          /* Walled City timed push-block puzzle A - countdown displayed; raised with GAMEBIT_WC_PushBlockTimerActive while A runs and cleared on solve, timeout or abort */
    GAMEBIT_SH_Related0EDE = 0xEDE,                      /* table 2; Triggers a communication after pushing switch at bottom of well */
    GAMEBIT_DFP_RotatepRingActive = 0xEDF,               /* The DLL names this one itself: DFP_ROTATEP_GAMEBIT_RING_ACTIVE in 562_DFP_RotateP.h */
    GAMEBIT_OFB_MaybeEnabled0EE0 = 0xEE0,                /* Named from map data alone - nothing in the code or in any name list mentions it: kraztest/VFP_flamepo objId= param=maybeEnabled; table 2 */
    GAMEBIT_OFB_DFPseqpoinDisable0EE1 = 0xEE1,           /* A DFP sequence point's disable bit, from its placement's field at 0x20. Two of the ids that slot holds - 0xCB1 and 0xEE0 - were already named from other evidence, which is what vindicates the slot; DfpSeqPointPlacement overruns the 0x24 record at its tail, but this field is inside it */
    GAMEBIT_WC_SeqBit1A0EE2 = 0xEE2,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit1A; table 2 */
    GAMEBIT_WC_SeqBit180EE3 = 0xEE3,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/WCSeqObject objId= param=bit18; table 2 */
    GAMEBIT_DR_SeqBit180EE4 = 0xEE4,                     /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/DR_Seqobj objId= param=bit18; table 2 */
    GAMEBIT_ITEM_SnowHornArtifactEE5 = 0xEE5,            /* table 2; set when using artifact */
    GAMEBIT_ITEM_SnowHornArtifactEE6 = 0xEE6,            /* table 2; set when using artifact */
    GAMEBIT_WC_GroundQuakePressed0EE8 = 0xEE8,           /* Read out of the retail placement data: wallcity/GroundQuake pressedGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_WC_FinalPuzzleRelated0EEC = 0xEEC,           /* Cleared alongside the stopwatch and animator bits as the Walled City final puzzle completes; nothing in the code sets it or reads it, and Rena records no objref */
    GAMEBIT_WC_HitAnimTarget0EED = 0xEED,                /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/HitAnimator objId= param=target; table 1 */
    GAMEBIT_WC_HitAnimTarget0EEE = 0xEEE,                /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/HitAnimator objId= param=target; table 2 */
    GAMEBIT_WM_Param200EEF = 0xEEF,                      /* Named from map data alone - nothing in the code or in any name list mentions it: warlock/WM_seqpoint objId= param=_20; table 2 */
    GAMEBIT_WC_SunInsideClosedLatch0EF0 = 0xEF0,         /* Read out of the retail placement data: wallcity/WCSunInside closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_WC_TrexAnimTarget0EF1 = 0xEF1,               /* Wallcity HitAnimator 0x4CB88's target - raised while a T-rex run is being armed and cleared on both of the run's endings */
    GAMEBIT_WC_SunInsideClosedLatch0EF2 = 0xEF2,         /* Read out of the retail placement data: wallcity/WCSunInside closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_OFB_DFPBridgeClosedLatch0EF4 = 0xEF4,        /* Read out of the retail placement data: kraztest/DFP_Bridge closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_OFB_DFPBridgeClosedLatch0EF5 = 0xEF5,        /* Read out of the retail placement data: kraztest/DFP_Bridge closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_VFP_EnvironmentRelated0EF6 = 0xEF6,           /* table 2; transporter-controlled VFP environment state */
    GAMEBIT_OFP_SeqPointTriggered0EF7 = 0xEF7,           /* Raised by DFP_seqpoin the update its own pending flag comes up, which it then clears */
    GAMEBIT_WC_Activate0EF9 = 0xEF9,                     /* Named from map data alone - nothing in the code or in any name list mentions it: wallcity/TrigPln objId= param=activate; table 1 */
    GAMEBIT_IN_KRAZOA_SHRINE = 0xEFA,                    /* table 0; set while any Krazoa shrine test is active */
    GAMEBIT_MC_IsActive = 0xEFB,                         /* table 0; set while the Magic Cave interior is active; selects SFX global control 0xD */
    GAMEBIT_MAZEWELL_ACTIVE = 0xEFC,                     /* table 0; Music_Trigger(0x36) + Well active/hitbox state */
    GAMEBIT_SETPIECE_ACTIVE = 0xEFD,                     /* table 0; set 1 for the duration of a major scripted encounter/arena (DIMboss boss fight, KT_RexLevel arena, nwsh_levcon chase) and cleared on exit; read by audio.c's Sfx_UpdateObjectSounds alongside GAMEBIT_IN_KRAZOA_SHRINE/MC_IsActive/MAZEWELL_ACTIVE/PlayerInShop to select the SFX global-control ducking level */
    GAMEBIT_PlayerInShop = 0xEFE,                        /* table 0 */
    GAMEBIT_DR_FireCrawlerDeadEFF = 0xEFF,               /* Rena's U0 dataset; table 2 */
    GAMEBIT_DR_FireCrawlerDeadF00 = 0xF00,               /* Rena's U0 dataset; table 2 */
    GAMEBIT_DR_HitAnimTarget0F02 = 0xF02,                /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/HitAnimator objId= param=target; dragrock/CAMERAnewse objId= param=needBit; table 2 */
    GAMEBIT_DR_SeqUsed0F03 = 0xF03,                      /* Named from map data alone - nothing in the code or in any name list mentions it: dragrock/CAMERAnewse objId= param=usedBit; table 2 */
    GAMEBIT_DIM2_LavaControl0F04 = 0xF04,                /* The DLL names this one itself: DIM2_LAVA_CONTROL_GAMEBIT_0F04 in DIM2LavaCon.c */
    GAMEBIT_CF_LargeCrateBroken0F06 = 0xF06,             /* Read out of the retail placement data: fortress/LargeCrate brokenGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_LV_LocatedKrazoaShrine = 0xF07,              /* table 0; hint 351 */
    GAMEBIT_NW_DidPadHornTest = 0xF08,                   /* table 0; hint 379 */
    GAMEBIT_WM_Activate0F09 = 0xF09,                     /* Named from map data alone - nothing in the code or in any name list mentions it: warlock/TrigPln objId= param=activate; table 0 */
    GAMEBIT_PlayerBoardedVehicle0F0A = 0xF0A,            /* table 0; raised where the player boards vehicle type 0x72, and only while standing in map cell 0x13 */
    GAMEBIT_DR_MusicLatch0F0E = 0xF0E,                   /* Dragon Rock - drmusiccont's GameBitLatch condition for music trigger 0xE5, cleared by 0x1A7 when set and by GAMEBIT_SH_Landed064B when clear */
    GAMEBIT_MapBits = 0xF10,                             /* table 2; up to F1C? */
    GAMEBIT_WorldMap_DragonRock = 0xF11,                 /* Rena's U0 dataset; table 2 */
    GAMEBIT_IM_Unk0F12 = 0xF12,                          /* table 2; set when first entering */
    GAMEBIT_WorldMap_WalledCity = 0xF13,                 /* Rena's U0 dataset; table 2 */
    GAMEBIT_WorldMap_LightFoot = 0xF14,                  /* Rena's U0 dataset; table 2 */
    GAMEBIT_TitleScreenRelated0F15 = 0xF15,              /* table 2; set at some point on file select */
    GAMEBIT_ArwingRelated0F16 = 0xF16,                   /* table 2; set in 1st Arwing level - if cleared, immediately sets again */
    GAMEBIT_WorldMap_DarkIce = 0xF17,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_WorldMap_OceanForce = 0xF18,                 /* Rena's U0 dataset; table 2 */
    GAMEBIT_WorldMap_MoonMountain = 0xF19,               /* Rena's U0 dataset; table 2 */
    GAMEBIT_WorldMap_Volcano = 0xF1A,                    /* Rena's U0 dataset; table 2 */
    GAMEBIT_WorldMap_CloudRunner = 0xF1B,                /* Rena's U0 dataset; table 2 */
    GAMEBIT_WorldMap_CapeClaw = 0xF1C,                   /* Rena's U0 dataset; table 2 */
    GAMEBIT_SC_TotemStrengthSequenceActive = 0xF1D,      /* The DLL names this one itself: SC_TOTEM_STRENGTH_GAMEBIT_SEQUENCE_ACTIVE in SC_totemstr.c */
    GAMEBIT_SB_CanShootPropeller = 0xF1E,                /* Rena's U0 dataset; table 2. Three readings, all of one galleon-fight phase: SB_Galleon sets it as a dive begins and clears it as that ends, SB_Cloudrun gates the CloudRunner's hit SFX on it, and Rena's name has it as when the propeller can be shot */
    GAMEBIT_OFT_SeqBit180F1F = 0xF1F,                    /* Named from map data alone - nothing in the code or in any name list mentions it: dfptop/CAMERAseqob objId= param=bit18; table 2 */
    GAMEBIT_SHBOT_SfxPlayerBit0F20 = 0xF20,              /* Read out of the retail placement data: hollow2/sfxPlayer gameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_SHBOT_XYZAnimatorCompletion0F21 = 0xF21,     /* Read out of the retail placement data: hollow2/XYZAnimator completionGameBit x1; hollow2/sfxPlayer gameBit x1; 2 placements. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_NW_RescueBush1Cleared = 0xF22,               /* SnowHorn Gate Keeper rescue: tumbleweed bush cleared marker reset by NW_levcontr and consumed by NW_mammoth */
    GAMEBIT_NW_RescueBush2Cleared = 0xF23,               /* SnowHorn Gate Keeper rescue: tumbleweed bush cleared marker reset by NW_levcontr and consumed by NW_mammoth */
    GAMEBIT_NW_RescueBush3Cleared = 0xF24,               /* SnowHorn Gate Keeper rescue: tumbleweed bush cleared marker reset by NW_levcontr and consumed by NW_mammoth */
    GAMEBIT_NW_RescueBush4Cleared = 0xF25,               /* SnowHorn Gate Keeper rescue: tumbleweed bush cleared marker reset by NW_levcontr and consumed by NW_mammoth */
    GAMEBIT_CC_LevelControlGoldBarCompletionSfx = 0xF26, /* The DLL names this one itself: CC_LEVEL_CONTROL_GOLD_BAR_COMPLETION_SFX_GAMEBIT in CClevcontro.c */
    GAMEBIT_WM_Open0F27 = 0xF27,                         /* Named from map data alone - nothing in the code or in any name list mentions it: warlock/WMFinalDoor objId= param=open; table 2 */
    GAMEBIT_WM_FinalDoorClosedLatch0F28 = 0xF28,         /* Read out of the retail placement data: warlock/WMFinalDoor closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DFSH_XYZAnimatorCompletion0F29 = 0xF29,      /* Read out of the retail placement data: dfshrine/XYZAnimator completionGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_DFSH_SfxPlayerBit0F2A = 0xF2A,               /* Read out of the retail placement data: dfshrine/sfxPlayer gameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_OFB_DFPRoundDoClosedLatch0F2C = 0xF2C,       /* Read out of the retail placement data: kraztest/DFP_RoundDo closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_OFB_DFPRoundDoClosedLatch0F2D = 0xF2D,       /* Read out of the retail placement data: kraztest/DFP_RoundDo closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_OFB_DFPRoundDoClosedLatch0F2E = 0xF2E,       /* Read out of the retail placement data: kraztest/DFP_RoundDo closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_OFB_DFPRoundDoClosedLatch0F2F = 0xF2F,       /* Read out of the retail placement data: kraztest/DFP_RoundDo closedLatchGameBit x1; 1 placement. Nothing in the code names it and no objref lists it - the object def and the Placement field are all the evidence there is */
    GAMEBIT_CountdownTimerRunning = 0xF31,               /* A countdown is running: NW_levcontr writes its own timer-active flag straight into it and latches its timer-end music off it, and WCLevelCont writes the same flag computed from the push-block timer, GAMEBIT_WC_StopwatchEnabled and gameTimerIsRunning */
    GAMEBIT_VFP_Param200F32 = 0xF32,                     /* Named from map data alone - nothing in the code or in any name list mentions it: temple/VFP_seqpoin objId= param=_20; table 2 */
    GAMEBIT_MMP_LevelControlEnvironmentB = 0xF33,        /* The DLL names this one itself: MMP_LEVEL_CONTROL_GAMEBIT_ENVIRONMENT_B in MMP_levelco.c */
    GAMEBIT_ITEM_CheatToken0_Used = 0xF34,               /* table 2; Display Credits. Backs the collectable item C-menu entry the game labels "Drop Token" (its used bit) */
    GAMEBIT_ITEM_CheatToken3_Used = 0xF35,               /* table 2; Dino Language. Backs the collectable item C-menu entry the game labels "Drop Token" (its used bit) */
    GAMEBIT_ITEM_CheatToken2_Used = 0xF36,               /* table 2; Music Test. Backs the collectable item C-menu entry the game labels "Drop Token" (its used bit) */
    GAMEBIT_ITEM_CheatToken6_Used = 0xF37,               /* table 2. Backs the collectable item C-menu entry the game labels "Drop Token" (its used bit) */
    GAMEBIT_ITEM_CheatToken4_Used = 0xF38,               /* table 2. Backs the collectable item C-menu entry the game labels "Drop Token" (its used bit) */
    GAMEBIT_ITEM_CheatToken7_Used = 0xF39,               /* table 2. Backs the collectable item C-menu entry the game labels "Drop Token" (its used bit) */
    GAMEBIT_ITEM_CheatToken1_Used = 0xF3A,               /* table 2; Sepia Mode. Backs the collectable item C-menu entry the game labels "Drop Token" (its used bit) */
    GAMEBIT_ITEM_CheatToken5_Used = 0xF3B,               /* table 2. Backs the collectable item C-menu entry the game labels "Drop Token" (its used bit) */
    GAMEBIT_SH_ToldGetViewFinder = 0xF3E,                /* table 2; Set when arriving after getting 4th stone; triggers a communication if you don't have viewfinder */
    GAMEBIT_OFB_ClawDeadF3F = 0xF3F,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_OFB_ClawDeadF40 = 0xF40,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_OFT_ClawDeadF41 = 0xF41,                     /* Rena's U0 dataset; table 2 */
    GAMEBIT_WM_Warp3Enabled = 0xF43,                     /* table 2; ref warlock/Transporter enabled */
    GAMEBIT_WM_Warp4Enabled = 0xF44,                     /* table 2; ref warlock/Transporter enabled */
    GAMEBIT_WM_SwitchDoorOpen = 0xF45,                   /* table 2; pressure switch is pressed (resets automatically) */
    GAMEBIT_WM_PressureSwitchDoor0F46 = 0xF46,           /* The door bit DLL 510's pressure switch uses for placement ident 0x47293, as it uses GAMEBIT_WM_SwitchDoorOpen for ident 0x1F1A; Rena places it in warlock */
    GAMEBIT_WM_HitAnimTarget0F47 = 0xF47,                /* Named from map data alone - nothing in the code or in any name list mentions it: warlock/HitAnimator objId= param=target; table 2 */
    GAMEBIT_WM_HitAnimTarget0F48 = 0xF48,                /* Named from map data alone - nothing in the code or in any name list mentions it: warlock/HitAnimator objId= param=target; table 2 */
    GAMEBIT_CF_ClawDeadF49 = 0xF49,                      /* Rena's U0 dataset; table 2 */
    GAMEBIT_CF_ClawDeadF4A = 0xF4A,                      /* Rena's U0 dataset; table 2 */
    GAMEBIT_WM_SwitchRelated0F47 = 0xF47                 /* table 2; related to KP pressure-switch door */
};

#endif /* MAIN_GAMEBIT_IDS_H_ */
