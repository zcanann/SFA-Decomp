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
