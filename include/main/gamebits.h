#ifndef MAIN_GAMEBITS_H_
#define MAIN_GAMEBITS_H_

#include "global.h"

u32 GameBit_Get(int eventId);
void GameBit_Set(int eventId, int value);

/*
 * GameBitId - symbolic ids for the game's persistent quest/story/event flags,
 * the integer `eventId` passed to GameBit_Get / GameBit_Set / gameBitIncrement.
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
     * via the caught GameBit_Set; it also gates the enemy's respawn (clearing it
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
     * fn_80296518(player, 0x08, 1) to set the spirit bit in playerStatus). It is
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
     * GameBit_Set(state->sequenceGameBit) in wmspiritplace_update - i.e.
     * DATA-DRIVEN, so no GameBit_Set(0x316) literal exists (which is why a code
     * grep finds no setter; traced live in Dolphin by catching the write, with
     * r28 == 0x316*4 and the wmspiritplace object in r27). Read as a code
     * literal by dll_012C_transporter.c - one of the three 0xBA8/0x316/0x511
     * guard bits that lock out the K1 return pad once you progress.
     */
    GAMEBIT_K1_SPIRIT_DEPOSITED = 0x316,

    /*
     * World map / Arwing flight-select is available. worldplanet_init force-sets
     * this (GameBit_Set(0xA63, 1)) every time the map opens, and
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
     * arwarwing_update (polling GameBit_Get(0x9d8)) branch on it. Transient -
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
     * watchpoint that caught GameBit_Set(0x18b, 1) at sh_staff_update+0x190
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
     *      the single enter-command GameBit_Set(0x239,1). Staff-gating is
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
     * - iff GameBit_Get(gWorldPlanetGameBitTable[i]) != 0, so each of these bits
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
     * prints the real name when GameBit_Get(gTaskHintTable[idx].bit_id) != 0 and
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
    GAMEBIT_WORLDMAP_NAME_DRAGON_ROCK   = 0xA67
};


/* extern-cleanup: consolidated prototypes (true-def sigs) */
void hudFn_8011f6f0(u8 x);
void hudDrawMagicBar(int alpha, int unk2, u32 flags);

#endif /* MAIN_GAMEBITS_H_ */
