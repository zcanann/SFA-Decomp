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
    FLAGS_GEAR,
    FLAGS_SUPPLIES,
    FLAGS_KEYS,
    FLAGS_STONES
};
typedef struct PracticeBitLabel {
    const char* name;
    u16 id;
    u8 page;
    u8 map;
} PracticeBitLabel;
#define ITEM(label, id)      {label, GAMEBIT_##id, FLAGS_INVENTORY, 0}
#define SUPPLY(label, id)    {label, GAMEBIT_##id, FLAGS_INVENTORY, 1}
#define KEY(label, id)       {label, GAMEBIT_##id, FLAGS_INVENTORY, 2}
#define STONE(label, id)     {label, GAMEBIT_##id, FLAGS_INVENTORY, 3}
#define SPELL(label, id)     {label, GAMEBIT_##id, FLAGS_SPELLS, 0}
#define TRICKY(label, id)    {label, GAMEBIT_##id, FLAGS_TRICKY, 0}
#define AREA(map, label, id) {label, GAMEBIT_##id, FLAGS_AREA, map}
#define UNUSED(label, id)    {label, GAMEBIT_##id, FLAGS_UNUSED, 0}
static const PracticeBitLabel practiceBits[] = {
    ITEM("STAFF", ITEM_Staff_Got),
    ITEM("FIREFLY LANTERN", ITEM_FireflyLantern_Got),
    SUPPLY("FIREFLIES", ITEM_Firefly_Count),
    SUPPLY("BOMB SPORES", ITEM_BombSpore_Count),
    SUPPLY("FUEL CELLS", ITEM_FuelCell_Count),
    SUPPLY("MOON SEEDS", ITEM_MoonSeed_Count),
    SUPPLY("WHITE GRUBTUBS", ITEM_WhiteShroom_Count),
    SUPPLY("FIRE GEMS", ITEM_FireGem_Count),
    SUPPLY("FIRE WEEDS", ITEM_FireWeed_Count),
    SUPPLY("GOLD BARS", ITEM_CCGoldBar_Count),
    ITEM("50 SCARAB BAG", ITEM_50ScarabBag_Got),
    ITEM("100 SCARAB BAG", ITEM_100ScarabBag_Got),
    ITEM("200 SCARAB BAG", ITEM_200ScarabBag_Got),
    ITEM("BAFOMDAD HOLDER", ITEM_BafomdadHolder_Got),
    ITEM("DINO HORN", ITEM_DinoHorn_Got),
    ITEM("VIEWFINDER", ITEM_Viewfinder_Got),
    STONE("FIRE SPELLSTONE 1", ITEM_FireSpellStone1_Got),
    STONE("WATER SPELLSTONE 1", ITEM_WaterSpellStone1_Got),
    STONE("FIRE SPELLSTONE 2", ITEM_FireSpellStone2_Got),
    STONE("WATER SPELLSTONE 2", ITEM_WaterSpellStone2_Got),
    KEY("GALLEON GOLD KEY", ITEM_WMGoldKey_Got),
    KEY("CLOUDRUNNER FLUTE", ITEM_Flute_Got),
    KEY("DIM COG 1", ITEM_DIMCog1_Got),
    KEY("DIM COG 2", ITEM_DIMCog2_Got),
    KEY("DIM COG 3", ITEM_DIMCog3_Got),
    KEY("DIM COG 4", ITEM_DIMCog4_Got),
    KEY("WALLED CITY SILVER TOOTH", ITEM_WCSilverTooth_Got),
    KEY("WALLED CITY GOLD TOOTH", ITEM_WCGoldTooth_Got),
    KEY("SHACKLE KEY", ITEM_DIMShackleKey_Got),
    KEY("CELL KEY", ITEM_DIM2CellKey_Got),
    KEY("SILVER KEY - MINES", ITEM_DIMSilverKey_Got),
    KEY("MOON PASS KEY", ITEM_MoonPassKey_Got),
    KEY("SUN STONE", ITEM_WCSunStone_Got),
    KEY("MOON STONE", ITEM_WCMoonStone_Got),
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
#undef STONE
#undef SPELL
#undef TRICKY
#undef AREA
#undef UNUSED
#endif
#endif
