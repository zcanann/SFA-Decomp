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
     * NOTE: the other two K1-pad guard bits, 0x316 and 0x511, have no setter in
     * code (set from save/level-event data), so their exact meaning is not yet
     * established - left as raw literals in dll_012C_transporter.c until traced.
     */

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
    GAMEBIT_K1_SPIRITDOORLOCK_PLAYER_APPROACHED = 0xab9
};


/* extern-cleanup: consolidated prototypes (true-def sigs) */
void hudFn_8011f6f0(u8 x);
void hudDrawMagicBar(int alpha, int unk2, u32 flags);

#endif /* MAIN_GAMEBITS_H_ */
