/* Curated practice labels, grounded in main/gamebit_ids.h. Unknown and unused
 * bits deliberately stay outside the ordinary inventory / spell pages. */
#ifndef PRACTICE_STATE_CATALOG_H
#define PRACTICE_STATE_CATALOG_H
#ifdef SFA_PRACTICE
#include "main/gamebit_ids.h"
enum {
    FLAGS_ROOT,
    FLAGS_INVENTORY,
    FLAGS_SPELLS,
    FLAGS_TRICKY,
    FLAGS_STATS,
    FLAGS_AREA,
    FLAGS_GROUPS,
    FLAGS_ADVANCED,
    FLAGS_RAW,
    FLAGS_UNUSED,
    FLAGS_UPGRADES,
    FLAGS_INVENTORY_SPELLS,
    FLAGS_CONSUMABLES,
    FLAGS_AREA_ITEMS,
    FLAGS_STONES,
    FLAGS_SPIRITS,
    FLAGS_MAPS,
    FLAGS_ITEM_AREA,
    FLAGS_DISCOVERY
};
enum {
    ITEM_AREA_GALLEON,
    ITEM_AREA_THORNTAIL,
    ITEM_AREA_DARKICE,
    ITEM_AREA_MOON_PASS,
    ITEM_AREA_CLOUDRUNNER,
    ITEM_AREA_CAPE_CLAW,
    ITEM_AREA_LIGHTFOOT,
    ITEM_AREA_WALLED_CITY
};
static const char* itemAreaNames[] = {
    "GALLEON",   "THORNTAIL HOLLOW",  "DARKICE MINES", "MOON MOUNTAIN PASS", "CLOUDRUNNER FORTRESS",
    "CAPE CLAW", "LIGHTFOOT VILLAGE", "WALLED CITY"};
typedef struct PracticeBitLabel {
    const char* name;
    u16 id;
    u8 page;
    u8 map;
} PracticeBitLabel;
#define ITEM(label, id)      {label, GAMEBIT_##id, FLAGS_INVENTORY, 0}
#define SUPPLY(label, id)    {label, GAMEBIT_##id, FLAGS_INVENTORY, 2}
#define KEY(area, label, id) {label, GAMEBIT_##id, FLAGS_ITEM_AREA, ITEM_AREA_##area}
#define MAP(label, id)       {label, GAMEBIT_##id, FLAGS_INVENTORY, 6}
#define STONE(label, id)     {label, GAMEBIT_##id, FLAGS_INVENTORY, 4}
#define SPIRIT(label, id)    {label, GAMEBIT_##id, FLAGS_INVENTORY, 5}
#define SPELL(label, id)     {label, GAMEBIT_##id, FLAGS_SPELLS, 0}
#define TRICKY(label, id)    {label, GAMEBIT_##id, FLAGS_TRICKY, 0}
#define AREA(map, label, id) {label, GAMEBIT_##id, FLAGS_AREA, map}
#define UNUSED(label, id)    {label, GAMEBIT_##id, FLAGS_UNUSED, 0}
#define DISCOVERY(label, id) {label, GAMEBIT_##id, FLAGS_DISCOVERY, 0}
static const PracticeBitLabel practiceBits[] = {
    ITEM("STAFF", ITEM_Staff_Got),
    ITEM("FIREFLY LANTERN", ITEM_FireflyLantern_Got),
    SUPPLY("FIREFLIES", ITEM_Firefly_Count),
    SUPPLY("BOMB SPORES", ITEM_BombSpore_Count),
    SUPPLY("FUEL CELLS", ITEM_FuelCell_Count),
    SUPPLY("MOON SEEDS", ITEM_MoonSeed_Count),
    ITEM("50 SCARAB BAG", ITEM_50ScarabBag_Got),
    ITEM("100 SCARAB BAG", ITEM_100ScarabBag_Got),
    ITEM("200 SCARAB BAG", ITEM_200ScarabBag_Got),
    ITEM("BAFOMDAD HOLDER", ITEM_BafomdadHolder_Got),
    ITEM("VIEWFINDER", ITEM_Viewfinder_Got),
    ITEM("TRICKY BALL BOUGHT", ITEM_TrickyBall_Bought),
    ITEM("TRICKY BALL USABLE", ITEM_TrickyBall_Usable),
    STONE("FIRE SPELLSTONE 1", ITEM_FireSpellStone1_Got),
    STONE("WATER SPELLSTONE 1", ITEM_WaterSpellStone1_Got),
    STONE("FIRE SPELLSTONE 2", ITEM_FireSpellStone2_Got),
    STONE("WATER SPELLSTONE 2", ITEM_WaterSpellStone2_Got),
    SPIRIT("KRAZOA 1 - OBSERVATION", K1_SPIRIT_COLLECTED),
    SPIRIT("KRAZOA 2 - COMBAT", ITEM_TestCombatSpirit_Got),
    SPIRIT("KRAZOA 3 - FEAR", ITEM_SpiritTestFear_Got),
    SPIRIT("KRAZOA 4 - STRENGTH", ITEM_SpiritTestStrength_Got),
    SPIRIT("KRAZOA 5 - KNOWLEDGE", ITEM_Spirit5_Got),
    SPIRIT("KRAZOA 6", ITEM_Spirit6_Got),
    KEY(GALLEON, "GOLD KEY", ITEM_WMGoldKey_Got),
    KEY(THORNTAIL, "WHITE GRUBTUBS", ITEM_WhiteShroom_Count),
    KEY(THORNTAIL, "FIRE WEEDS", ITEM_FireWeed_Count),
    KEY(DARKICE, "DINO HORN", ITEM_DinoHorn_Got),
    KEY(DARKICE, "COG 1", ITEM_DIMCog1_Got),
    KEY(DARKICE, "COG 2", ITEM_DIMCog2_Got),
    KEY(DARKICE, "COG 3", ITEM_DIMCog3_Got),
    KEY(DARKICE, "COG 4", ITEM_DIMCog4_Got),
    KEY(DARKICE, "SHACKLE KEY", ITEM_DIMShackleKey_Got),
    KEY(DARKICE, "CELL KEY", ITEM_DIM2CellKey_Got),
    KEY(DARKICE, "SILVER KEY", ITEM_DIMSilverKey_Got),
    KEY(MOON_PASS, "KEY", ITEM_MoonPassKey_Got),
    KEY(CLOUDRUNNER, "FLUTE", ITEM_Flute_Got),
    KEY(CAPE_CLAW, "FIRE GEMS", ITEM_FireGem_Count),
    KEY(CAPE_CLAW, "GOLD BARS", ITEM_CCGoldBar_Count),
    KEY(LIGHTFOOT, "WOOD BLOCK 1", ITEM_LVBlock1_Got),
    KEY(LIGHTFOOT, "WOOD BLOCK 2", ITEM_LVBlock2_Got),
    KEY(LIGHTFOOT, "WOOD BLOCK 3", ITEM_LVBlock3_Got),
    KEY(WALLED_CITY, "SILVER TOOTH", ITEM_WCSilverTooth_Got),
    KEY(WALLED_CITY, "GOLD TOOTH", ITEM_WCGoldTooth_Got),
    KEY(WALLED_CITY, "SUN STONE", ITEM_WCSunStone_Got),
    KEY(WALLED_CITY, "MOON STONE", ITEM_WCMoonStone_Got),
    MAP("THORNTAIL HOLLOW", ITEM_MapSH_Got),
    MAP("SNOWHORN WASTES", ITEM_MapNW_Got),
    MAP("DARKICE MINES", ITEM_MapDIM_Got),
    MAP("MOON MOUNTAIN PASS", ITEM_MapMMP_Got),
    MAP("CLOUDRUNNER FORTRESS", ITEM_MapCF_Got),
    MAP("CAPE CLAW", ITEM_MapCC_Got),
    MAP("LIGHTFOOT VILLAGE", ITEM_MapLV_Got),
    MAP("WALLED CITY", ITEM_MapWC_Got),
    MAP("DRAGON ROCK", ITEM_MapDR_Got),
    MAP("KRAZOA PALACE", ITEM_MapWM_Got),
    MAP("VOLCANO FORCE POINT", ITEM_MapVFP_Got),
    MAP("OCEAN FORCE POINT", ITEM_MapOFP_Got),
    SPELL("MAGIC UNLOCKED", ITEM_Magic_Got),
    SPELL("FIRE BLASTER", STAFF_ABILITY_FIRE_BLASTER),
    SPELL("SHARPCLAW DISGUISE", STAFF_ABILITY_SHARPCLAW_DISGUISE),
    SPELL("STAFF BOOSTER", ITEM_StaffBooster_Got),
    SPELL("OPEN PORTAL", ITEM_OpenPortal_Got),
    SPELL("ICE BLAST", ITEM_IceBlast_Got),
    SPELL("GROUND QUAKE", ITEM_GroundQuake_Got),
    SPELL("SUPER QUAKE", ITEM_SuperQuake_Got),
    SPELL("FIRE BLASTER DISABLED", ITEM_FireBlaster_Disabled),
    SPELL("BOOSTER DISABLED", ITEM_StaffBooster_Disabled),
    SPELL("PORTAL DISABLED", ITEM_PortalSpell_Disabled),
    SPELL("DISGUISE DISABLED", ITEM_SharpClawDisguise_Disabled),
    SPELL("SUPER QUAKE DISABLED", ITEM_SuperQuake_Disabled),
    TRICKY("COMMANDS UNLOCKED", Tricky_Unlocked_Sidekick_Commands),
    TRICKY("SPAWNING ALLOWED", Tricky_Spawns),
    TRICKY("RESCUED AT ICE MOUNTAIN", IM_RescuedTricky),
    TRICKY("ICE MOUNTAIN DONE", IM_Done),
    TRICKY("SAID GOODBYE", Tricky_SaidGoodBye),
    TRICKY("STAY / FIND", ITEM_TrickyStayFind_Got),
    TRICKY("CALL", ITEM_TrickyCall_Got),
    TRICKY("FLAME", ITEM_TrickyFlame_Got),
    TRICKY("DISTRACT / BADDIE ALERT", Tricky_Learned_Distract),
    TRICKY("FOOD", ITEM_TrickyFood_Count),
    TRICKY("FEEDING DISABLED", Tricky_CantFeed),
    TRICKY("BALL BOUGHT", ITEM_TrickyBall_Bought),
    TRICKY("BALL USABLE", ITEM_TrickyBall_Usable),
    TRICKY("BALL DISABLED", NoBallsAllowed),
    /* Separate one-shot introduction latches, not item ownership/counts.
     * CollectedFlag09A8 is the moon-seed case in collectible_checkProximityPickup. */
    DISCOVERY("STAFF ENERGY GEM", SawMagic),
    DISCOVERY("ENERGY EGG", SawBigHealth),
    DISCOVERY("DUSTER EGG / APPLE", SawApple),
    DISCOVERY("SCARAB", SawScarab),
    DISCOVERY("BOMB SPORE", SawBombSpore),
    DISCOVERY("FUEL CELL", SawFuelCell),
    DISCOVERY("BAFOMDAD", SawBafomdad),
    DISCOVERY("MOON SEED", CollectedFlag09A8),
    DISCOVERY("BOMB SPORE PLANT", SawBombPlant),
    DISCOVERY("BOMB SPORE PATCH", SawBombPlantPatch),
    DISCOVERY("WARP PAD", SawWarpPad),
    DISCOVERY("STAFF BOOST PAD", SawStaffBoostPad),
    DISCOVERY("BARREL GENERATOR", SawBarrelGen),
    DISCOVERY("C-MENU EXPLANATION", SawCMenuExplanation),
    AREA(7, "TALKED TO PEPPER", SH_TalkedToPepper),
    AREA(7, "FOUND QUEEN", SH_FoundQueen),
    AREA(7, "RETURNED TO QUEEN", SH_ReturnedToQueen),
    AREA(7, "RETURNED TO HOLLOW", SH_ReturnedToHollow),
    AREA(7, "WARPSTONE PATH OPEN", SH_WarpStonePathOpen),
    AREA(7, "WELL TUNNEL OPEN", SH_OpenedTunnelToWell),
    AREA(23, "TRICKY RESCUED", IM_RescuedTricky),
    AREA(23, "RACE STARTED", IM_RaceStarted),
    AREA(23, "START RACE", IM_StartRace),
    AREA(23, "ON BIKE", IM_OnBike),
    AREA(23, "ICE MOUNTAIN DONE", IM_Done),
    AREA(19, "FOUND INJURED SNOWHORN", DIM_FoundInjuredSnowHorn),
    AREA(19, "RELEASED SNOWHORN", DIM_ReleasedSnowHorn),
    AREA(12, "ENTERED FORT", CF_EnteredFort),
    AREA(12, "SAVED QUEEN", CF_SavedQueen),
    AREA(12, "GUARDIAN FREED", CF_GuardianFreed),
    AREA(12, "PRISON CAGE OPEN", CF_PrisonCageOpened),
    AREA(12, "POWER ON", CF_PowerOn),
    AREA(12, "ESCAPED DUNGEON", CF_EscapedDungeon),
    AREA(12, "RESCUED BABIES", CF_RescuedBabies),
    AREA(33, "SHRINE INTRO TRIGGER", K1_SHRINE_INTRO_TEXT_TRIGGER),
    AREA(33, "GATE MONSTER DEFEATED", K1_GATE_MONSTER_DEFEATED),
    AREA(33, "LIFEFORCE GATE OPEN", K1_LIFEFORCE_GATE_OPENED),
    AREA(33, "TEST RUNNING", ECSH_TestObservRunning),
    AREA(33, "SPIRIT COLLECTED", K1_SPIRIT_COLLECTED),
    AREA(33, "SPIRIT DEPOSITED", K1_SPIRIT_DEPOSITED),
    AREA(31, "SPIRIT COLLECTED", ITEM_TestCombatSpirit_Got),
    AREA(32, "SPIRIT COLLECTED", ITEM_SpiritTestFear_Got),
    AREA(34, "TEST RUNNING", GPSH_TestKnowledgeRunning),
    AREA(34, "SPIRIT COLLECTED", ITEM_Spirit5_Got),
    AREA(39, "SPIRIT COLLECTED", ITEM_SpiritTestStrength_Got),
    AREA(40, "ENTERED", K6_Entered),
    AREA(40, "SPIRIT COLLECTED", ITEM_Spirit6_Got),
    {"ICE BLAST UNAVAILABLE (961)", GAMEBIT_ITEM_Spell0961_Disabled, FLAGS_ROOT, 0},
    {"BLASTER UNAVAILABLE (965)", GAMEBIT_ITEM_Spell0965_Disabled, FLAGS_ROOT, 0},
    {"OUTDOOR EFFECTS", GAMEBIT_ENV_isOutdoor, FLAGS_ROOT, 0},
    {"WARPSTONE / TRANSPORT FLAG (884)", GAMEBIT_SH_WarpStoneRelated0884, FLAGS_AREA, 7},
    UNUSED("UNUSED LASER SPELL", ITEM_LaserSpell_Got),
    UNUSED("DELETED SPELL 5FC", ITEM_DeletedSpell5FC_Got),
    UNUSED("DELETED SPELL 777", ITEM_DeletedSpell777_Got),
    UNUSED("UNUSED? SPELLSTONE 7BD", ITEM_SpellStone7BD_Got),
    UNUSED("UNUSED? SPELLSTONE 83A", ITEM_SpellStone83A_Got),
    UNUSED("UNUSED SHOP ALERT", ITEM_BadGuyAlert_Got),
    UNUSED("UNCERTAIN TRICKY C11", MaybeHaveTricky),
};
#undef ITEM
#undef SUPPLY
#undef KEY
#undef MAP
#undef STONE
#undef SPIRIT
#undef SPELL
#undef TRICKY
#undef AREA
#undef UNUSED
#undef DISCOVERY
#endif
#endif
