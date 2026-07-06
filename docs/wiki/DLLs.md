# DLLs

> Source: [Rena Kunisaki's SFA wiki](https://github.com/RenaKunisaki/StarFoxAdventures/wiki/DLLs). Reverse-engineering notes; not independently verified here.

Like many N64 games, SFA originally used a "Dynamically Linked Library" (overlay) system to page code
in and out of RAM. On the GameCube port this system was kept but is mostly vestigial — every DLL's
code stays resident at all times, and "loading"/"unloading" a DLL now just bumps a reference counter.

DLLs don't have retail names; the names below are inferred from in-game objects and debug strings.
The highest valid ID is 0x2C1.

## DLL ID table

| ID | Name | Description |
|----|------|--------------|
| 000 | UI | HUD and menus |
| 001 | Camera |  |
| 002 | ObjSeq | Scripting |
| 004 | Dummy04 | all functions stubbed |
| 005 | Sky |  |
| 00C | projgfx |  |
| 013 | waterfx |  |
| 015 |  | related to hit detection |
| 017 | SaveGame |  |
| 031 | Minimap | PDA HUD |
| 034 | TitleMenu | title screen main menu |
| 035 | SaveSelectScreen | on title screen |
| 036 | EnterSaveNameScreen | on title screen |
| 037 | OptionsScreen | on title screen |
| 03A | Dummy3A | all functions stubbed |
| 03B | Menu | generic menus |
| 03C | Link | linked menus (eg title screen) |
| 040 | Credits |  |
| 041 | Warpstone |  |
| 044 | Viewfinder | zoom goggles |
| 04D | FeedTricky |  |
| 05A | IceSpell |  |
| 0C4 | Tricky |  |
| 0C6 | AnimatedObj |  |
| 0C7 | DIM2RoofRub |  |
| 0C8 | DepthOfFiel |  |
| 0C9 | EnemyC9 |  |
| 0C9 | HagabonMK2 | jellyfish/metroids |
| 0CC | ChukChuk |  |
| 0CD | IceBall |  |
| 0CF | CannonClaw | guy who operates cannons |
| 0D0 | Grimble |  |
| 0D1 | TumbleWeedB |  |
| 0D2 | Tumbleweed |  |
| 0D4 | SkeetlaWall |  |
| 0D5 | KaldaChomp |  |
| 0D6 | KaldaChompMe |  |
| 0D7 | KaldaChompSp |  |
| 0D8 | PinPonSpike |  |
| 0D9 | Pollen |  |
| 0DA | PollenFragment |  |
| 0DC | MikaBombSha |  |
| 0DD | GCbaddieShi |  |
| 0DE | baddieInter |  |
| 0DF | Hagabon |  |
| 0E0 | SwarmBaddie |  |
| 0E1 | WispBaddie |  |
| 0E2 | Staff |  |
| 0E3 | Fireball |  |
| 0E4 | FlameThrower |  |
| 0E5 | Shield |  |
| 0E6 | ReStartMark |  |
| 0E7 | FlammableVine |  |
| 0E8 | checkpoint4 |  |
| 0E9 | setuppoint |  |
| 0EA | sideload |  |
| 0EB | siderepel |  |
| 0EC | InfoPoint |  |
| 0ED | Collectible |  |
| 0EE | EffectBox |  |
| 0EF | Pushable |  |
| 0F0 | WarpPoint |  |
| 0F1 | InvHit |  |
| 0F2 | iceblast |  |
| 0F3 | flameblast |  |
| 0F4 | DoorF4 |  |
| 0F5 | SidekickBal |  |
| 0F6 | Area |  |
| 0F8 | LevelName | shows name on screen when entering |
| 0F9 | ProjectileS |  |
| 0FA | InvisibleHi |  |
| 0FB | PressureSwitchFB |  |
| 0FE | MagicPlant | gives magic gems |
| 0FF | MagicDust | magic gem |
| 100 | TrickyWarp |  |
| 101 | TrickyGuard |  |
| 102 | StayPoint |  |
| 103 | CurveFish |  |
| 104 | SmallBasket |  |
| 105 | LargeCrate |  |
| 106 | Scarab |  |
| 108 | EndObject |  |
| 10A | Fall_Ladder |  |
| 10B | FireFlyLant |  |
| 10C | LanternFire |  |
| 10D | PortalSpell |  |
| 10E | DeathSeq |  |
| 10F | MMP_Bridge |  |
| 110 | Door |  |
| 111 | DoorLock |  |
| 112 | SeqObj112 |  |
| 113 | SeqObj113 |  |
| 114 | IMMultiSeq |  |
| 116 | WM_Column |  |
| 117 | AppleOnTree |  |
| 118 | Duster | Bafomdad |
| 119 | coldWaterCo | makes you take damage in water |
| 11A | Decoration11A |  |
| 11B | Landed_Arwing |  |
| 11C | StaffActivated | switches you put staff into |
| 11D | TreasureChe |  |
| 11E | MagicCaveBo | interior warp of magic cave |
| 11F | MagicCaveTo | exterior warp of magic cave |
| 120 | TrickyGuard120 |  |
| 121 | InfoText |  |
| 122 | CCTestInfot |  |
| 123 | fuelCell |  |
| 124 | deathGas | in CloudRunner Fortress power chamber |
| 125 | curve |  |
| 126 | Trigger |  |
| 126 | TrigPnt |  |
| 128 | KT_Torch |  |
| 129 | CampFire |  |
| 12A | CFCrate |  |
| 12B | FXEmit |  |
| 12C | Transporter |  |
| 12D | LFXEmitter |  |
| 12E | InteractiveObj12E |  |
| 12F | BarrelPad |  |
| 130 | AreaFXEmit |  |
| 131 | CF_DoorLigh |  |
| 132 | WaterFallSp |  |
| 133 | sfxPlayer |  |
| 134 | texscroll2 |  |
| 135 | texscroll |  |
| 136 | WaveAnimato |  |
| 137 | AlphaAnimat |  |
| 138 | GroundAnima |  |
| 139 | HitAnimator |  |
| 13A | VisAnimator |  |
| 13B | WallAnimato |  |
| 13C | XYZAnimator |  |
| 13D | ExplodeAnim |  |
| 13E | DIMBossIceS |  |
| 13F | TexFrameAni |  |
| 140 | fogControl |  |
| 141 | Lightning |  |
| 142 | FElevContro |  |
| 143 | FEseqobject |  |
| 145 | CloudPrison |  |
| 146 | CloudShipCo |  |
| 148 | CFGuardian |  |
| 149 | WindLift |  |
| 14A | CFPowerBase |  |
| 14B | CFMainCryst |  |
| 14C | BabyCloudRunner |  |
| 14D | LaserBeam |  |
| 14E | CFPrisonGuard |  |
| 14F | CFPrisonUnc |  |
| 150 | GCRobotLight |  |
| 151 | CFScalesGal |  |
| 152 | CF_ObjCreat |  |
| 153 | CFPerch |  |
| 154 | CFPrisonCage |  |
| 157 | SpiritDoorS |  |
| 158 | GunPowderBarrel |  |
| 159 | Blasted |  |
| 15A | Explodable |  |
| 15B | CFForceField15B |  |
| 15C | CFForceField15C |  |
| 15D | SlidingDoor |  |
| 15F | Attractor |  |
| 161 | CFTreasRobo |  |
| 162 | CFMagicWall |  |
| 164 | CFLevelCont |  |
| 165 | CFRemovalSh |  |
| 166 | Exploded |  |
| 167 | SpiritDoorL |  |
| 168 | HoloPoint |  |
| 169 | IMIceMounta |  |
| 16A | CRrockfall |  |
| 16B | MagicLight |  |
| 16D | IMIcePillar |  |
| 16E | IMAnimSpace |  |
| 16F | IMSpaceThru |  |
| 170 | IMSpaceRing170 |  |
| 171 | IMSpaceRing171 |  |
| 172 | LINKB_levco |  |
| 173 | LINK_levcon |  |
| 174 | CCriverflow |  |
| 175 | DFropenode |  |
| 176 | DFSH_Door1S |  |
| 177 | DFSH_Door2S |  |
| 178 | DFSH_Shrine |  |
| 179 | DFSH_ObjCre |  |
| 17A | SpiritPrize |  |
| 17B | DFSH_LaserB |  |
| 17C | GCRobotPatr |  |
| 17D | RollingBarrel |  |
| 17E | MMP_levelco |  |
| 17F | MSBush |  |
| 180 | MMP_asteroi |  |
| 181 | MMP_trenchF |  |
| 182 | MMP_moonroc |  |
| 183 | MMP_gyserve |  |
| 184 | AnimShar |  |
| 185 | CCgasvent |  |
| 186 | CCgasventCo |  |
| 187 | CCqueen |  |
| 188 | CClightfoot |  |
| 189 | CCSharpclaw |  |
| 18A | CCpedstal |  |
| 18B | CClevcontro |  |
| 18C | MMSH_Shrine |  |
| 18D | MMSH_Scales |  |
| 18E | MMSH_WaterS |  |
| 18F | ECSH_Shrine |  |
| 190 | ECSH_Cup |  |
| 191 | ECSH_Creato |  |
| 192 | GPSH_Shrine |  |
| 193 | GPSH_ObjCre |  |
| 194 | GPSH_Scene |  |
| 195 | DBSH_Shrine |  |
| 196 | DBSH_Symbol |  |
| 198 | NWSH_levcon |  |
| 19F | TreeBird |  |
| 1A0 | NW_geyser |  |
| 1A1 | NW_mammoth |  |
| 1A2 | NW_tricky |  |
| 1A3 | NW_animice |  |
| 1A4 | NW_ice |  |
| 1A5 | NW_levcontr |  |
| 1A6 | SH_tricky |  |
| 1A7 | EdibleMushroom |  |
| 1A8 | EnemyMushroom |  |
| 1A9 | BombPlant |  |
| 1AA | BombPlantSp |  |
| 1AB | BombPlantin |  |
| 1AC | SH_queenear |  |
| 1AD | SH_thorntai |  |
| 1AE | SH_LevelCon |  |
| 1AF | WarpStoneLift |  |
| 1B0 | WarpStone |  |
| 1B1 | SH_staff | staff pickup in hollow |
| 1B2 | SH_staffHaz |  |
| 1B3 | SH_Beacon |  |
| 1B4 | SH_EmptyTum |  |
| 1B5 | LightFoot |  |
| 1B6 | SC_levelcon |  |
| 1B7 | SC_MusicTree |  |
| 1B8 | SC_totempol |  |
| 1B9 | SC_Cloudrun |  |
| 1BA | SC_totempuz |  |
| 1BB | SC_totembon |  |
| 1BC | SC_totemstr |  |
| 1BD | PaymentKiosk | for cheat tokens, Cape Claw entrance |
| 1BE | LavaBall1BE |  |
| 1BF | LavaBall1BF |  |
| 1C0 | DIMLogFire |  |
| 1C1 | DIMSnowBall1C1 |  |
| 1C2 | DIMSnowBall1C2 |  |
| 1C3 | DIMGate |  |
| 1C4 | DIMIceWall |  |
| 1C5 | DIMBarrier |  |
| 1C6 | DIMCannon |  |
| 1C7 | DIMLavaSmas |  |
| 1C8 | DIMBridgeCo |  |
| 1C9 | DIMDismount |  |
| 1CA | DIMExplosio |  |
| 1CB | DIMWoodDoor |  |
| 1CC | DIMMagicBri |  |
| 1CD | DIM_LevelCo |  |
| 1D0 | DIM_tricky |  |
| 1D1 | DIMTruthHor |  |
| 1D2 | WORLDplanet |  |
| 1D3 | WorldMapObj |  |
| 1D4 | WORLDAstero |  |
| 1D5 | DIM2Conveyo |  |
| 1D7 | DIM2SnowBal |  |
| 1D8 | DIM2PathGen |  |
| 1D9 | DIM2PrisonM |  |
| 1DC | DIM2IceFloe |  |
| 1DD | DIM2Icicle |  |
| 1DE | DIM2LavaCon |  |
| 1E0 | DIM_Boss |  |
| 1E1 | DIM_BossGut |  |
| 1E2 | DIM_BossTon |  |
| 1E3 | DIM_BossGut2 |  |
| 1E4 | MAGICMaker |  |
| 1E5 | DIM_BossSpi |  |
| 1E6 | DIMbosscrac |  |
| 1E7 | DIMbossfire |  |
| 1E8 | SB_Galleon |  |
| 1E9 | SB_Propeller |  |
| 1EA | SB_ShipHead |  |
| 1EB | SB_ShipMast |  |
| 1EC | SB_ShipGun |  |
| 1ED | SB_FireBall |  |
| 1EE | SB_CannonBa |  |
| 1EF | SB_CloudBal |  |
| 1F0 | SB_KyteCage |  |
| 1F1 | SB_SeqDoor |  |
| 1F2 | SB_CageKyte |  |
| 1F3 | SB_MiniFire |  |
| 1F4 | Lamp |  |
| 1F5 | ShipBattle |  |
| 1F6 | Flag |  |
| 1F7 | SB_ShipGunB |  |
| 1F8 | WM_Galleon |  |
| 1F9 | WM_ObjCreat |  |
| 1FA | WM_seqobjec |  |
| 1FC | LaserBeam1FC |  |
| 1FD | WM_LaserTar |  |
| 1FE | PressureSwitch |  |
| 201 | WM_colrise |  |
| 204 | WM_Torch |  |
| 205 | WM_Vein |  |
| 206 | LightSource |  |
| 207 | WM_Worm |  |
| 208 | WM_Wallpowe |  |
| 209 | WM_LevelCon |  |
| 20A | WM_GeneralS |  |
| 20B | FireFly |  |
| 20C | WM_spiritpl |  |
| 20D | WM_seqpoint |  |
| 20E | WM_sun |  |
| 20F | WM_SpiritSe |  |
| 210 | WM_PlanetsS |  |
| 211 | WM_WallCraw |  |
| 213 | WM_VConsole |  |
| 214 | WM_TransTop |  |
| 215 | WM_newcryst |  |
| 216 | VFP_LevelCo |  |
| 217 | VFP_ObjCrea |  |
| 218 | VFP_MiniFir |  |
| 21A | VFP_statueb |  |
| 21C | VFP_Ladders |  |
| 21D | VFPLift |  |
| 21E | VFP_Block1 |  |
| 21F | VFP_Platfor |  |
| 220 | VFP_DoorSwi |  |
| 221 | SeqPoint |  |
| 222 | VFPDragHead |  |
| 223 | VFP_corepla |  |
| 225 | VFP_flamepo |  |
| 226 | VFP_lavapoo |  |
| 227 | VFP_lavasta |  |
| 228 | VFP_SpellPl |  |
| 229 | DFP_LevelCo |  |
| 22A | DFP_ObjCrea |  |
| 22B | DFP_Torch |  |
| 22D | DFP_seqpoin |  |
| 22E | DoorSwitch |  |
| 22F | DFP_floorba |  |
| 230 | DFP_wallbar |  |
| 231 | DFP_ForceAw |  |
| 232 | DFP_RotateP |  |
| 233 | DFP_Statue1 |  |
| 234 | dfperchwitch |  |
| 235 | DFP_TargetB |  |
| 236 | Laser |  |
| 237 | DFPSpPl |  |
| 238 | LINKA_levco |  |
| 239 | TextBlock |  |
| 23A | Platform1 |  |
| 23B | DFP_Lightni |  |
| 23C | DFP_PowerSl |  |
| 23D | DBPointMum |  |
| 23F | DB_egg |  |
| 240 | GCRobotBlast |  |
| 241 | DrakorEnerg |  |
| 242 | DBstealerwo | egg thieves |
| 243 | DBHoleContr | holes for egg thieves |
| 24C | BossDrakor24C |  |
| 24D | BossDrakor |  |
| 24E | DrakorD_ThornBush |  |
| 24F | KT_RexLevel |  |
| 250 | KT_Rex |  |
| 251 | KT_RexFloor |  |
| 252 | KT_Lazerwal |  |
| 253 | KT_Lazerlig |  |
| 254 | KT_Fallingr |  |
| 255 | SnowBike |  |
| 256 | DIMSnowHorn |  |
| 257 | DR_EarthWar |  |
| 258 | DR_CloudRun |  |
| 259 | SB_CloudRun |  |
| 25A | StaticCamera |  |
| 25B | MSPlantingS |  |
| 25C | SnowClaw | blue SharpClaw |
| 25D | CRCloudRace |  |
| 25E | FireSpellStone |  |
| 25F | CRFuelTank |  |
| 260 | ProximityMine |  |
| 261 | DR_LaserCan |  |
| 262 | DrakorMissile |  |
| 263 | GM_MazeWell |  |
| 265 | DR_Creator |  |
| 266 | KytesMum |  |
| 268 | DR_CageCont |  |
| 269 | ExplodePlan |  |
| 26A | DR_Geezer |  |
| 26B | DR_Chimmey |  |
| 26C | DR_CageWith |  |
| 26D | DR_Vines |  |
| 26E | DR_Shackle |  |
| 26F | DR_Generato |  |
| 270 | DR_Rock |  |
| 271 | DrakorHover |  |
| 272 | HighTop |  |
| 273 | FirePipe |  |
| 274 | DR_pulley |  |
| 275 | DR_cradle |  |
| 277 | CFWindLiftL |  |
| 278 | DRCollapseP |  |
| 279 | DR_EnergyDi |  |
| 27A | DR_Collapse |  |
| 27B | DR_CaveIn |  |
| 27C | DR_LightBea |  |
| 27E | DRMusicCont |  |
| 27F | DR_LightHal |  |
| 280 | DR_CloudPer |  |
| 281 | DR_EarthCal |  |
| 282 | BarrelGener |  |
| 283 | DR_BarrelGr |  |
| 284 | ShopItem |  |
| 285 | Shop |  |
| 286 | ShopKeeper |  |
| 287 | SPScarab |  |
| 288 | SPDrape |  |
| 289 | SPitembeam |  |
| 28A | EarthWalker |  |
| 28C | WCBouncyCra |  |
| 28D | WCLevelCont |  |
| 28E | WCBeacon |  |
| 28F | WCPressureS |  |
| 290 | WCPushBlock |  |
| 291 | WCTile |  |
| 292 | WCTrexStatu |  |
| 293 | SunTemple |  |
| 294 | WCTemple |  |
| 295 | WCApertureS |  |
| 296 | WCTempleDia |  |
| 297 | WCTempleBri |  |
| 298 | WCFloorTile |  |
| 29A | ARWArwing |  |
| 29B | ArwingAndrossStuff |  |
| 29C | ARWArwingBo |  |
| 29D | ARWArwingGu |  |
| 29F | ARWBombColl |  |
| 2A0 | Ring |  |
| 2A1 | ARWLevelCon |  |
| 2A2 | ARWSpeedStr |  |
| 2A5 | ARWGenerato |  |
| 2A6 | ARWSquadron |  |
| 2A7 | ARWProximit |  |
| 2A8 | ARWBlocker |  |
| 2A9 | PointLight |  |
| 2AA | DirectionalLight |  |
| 2AB | ProjectedLight |  |
| 2AC | ControlLight |  |
| 2AD | SoftBody |  |
| 2AE | WaterFlowWe |  |
| 2AF | Tree |  |
| 2B0 | BrokenPipe |  |
| 2B1 | CmbSrc |  |
| 2B2 | DustMoteSou |  |
| 2B3 | Vortex |  |
| 2B4 | CNTcounter |  |
| 2B5 | Timer |  |
| 2B6 | CNThitObjec |  |
| 2B7 | MCUpgrade |  |
| 2B8 | MCUpgradeMa |  |
| 2B9 | MCStaffEffe |  |
| 2BA | MCLightning |  |
| 2BB | GF_LevelCon |  |
| 2BC | Andross |  |
| 2BD | AndrossHand |  |
| 2BE | AndrossBrain |  |
| 2BF | AndrossLigh |  |
| 2C0 | FrontPilots |  |
| 2C0 | TitleScreen |  |

## In this codebase

Cross-references verified by reading the source at the paths below.

### The DLL table and the "reference counter" load/unload

The wiki's "loading/unloading a DLL just changes a reference counter" claim is exactly
`Resource_Acquire`/`Resource_Release` in `src/main/modelEngine.c`:

- `ResourceDescriptor* gResourceDescriptors[]` (`src/main/modelEngine.c:725`) is the master table,
  indexed **directly by DLL ID** — a 706-entry (`0x2C2`) array of pointers to per-DLL descriptor
  structs. `ResourceDescriptor` itself (`include/main/engine_shared.h:283`) is `{ pad[0x10];
  acquire(); release(); data[]; }`.
- `Resource_Acquire(u32 id, ...)` (`modelEngine.c:255`) does `index = id & 0xffff`, calls
  `descriptor->acquire()` only on the 0→1 refcount transition (`gResourceRefCounts[index]`, a
  `u16[0x2C2]`), then always increments the count and returns a loaded-handle slot.
  `Resource_Release` (`modelEngine.c:224`) is the mirror: decrement, and only call `->release()`
  when the count hits zero. This is precisely the wiki's "nothing but change a reference counter"
  behaviour — the *first* acquire/last release still runs real init/teardown code, everything
  in between is a no-op counter bump.
- `RESOURCE_DESCRIPTOR_COUNT` is `#define`d `0x2c1` (`modelEngine.c:8`) and bounds the
  `Resource_Acquire`/`Reset` loops — matching the wiki's "highest valid ID is 0x2C1" almost exactly.
  The array itself carries one extra trailing entry at index `0x2C1`, which is `NULL` — i.e. the
  table's *span* is `0x2C1` valid IDs (`0`..`0x2C0`), and index `0x2C0` (`gTitleScreenObjDescriptor`,
  matching the wiki's dual `2C0 FrontPilots`/`TitleScreen` row) is the last real slot.
- A second, narrower load/unload path exists for the single "current UI DLL" (front-end screens):
  `loadUiDll(int index)` / `set_uiDllIdx_803dc8f0` / `getCurUiDll` (`modelEngine.c:451-471`), gated
  through `gModelEnginePendingUiDll`/`gModelEngineCurUiDllRes` and going through the same
  `Resource_Release`/`Resource_Acquire` pair — this is what backs DLL 0 ("UI") and the title-screen
  DLL family (0x32-0x44) swapping in and out as the player navigates menus.

### The per-object vtable (why "Dummy04"/"Dummy3A" are "all functions stubbed")

Each object-handling DLL slot's descriptor is one of the `ObjectDescriptor*` variable-length structs
in `include/main/object_descriptor.h` — a fixed prefix (`reserved0..2`, `slotCountAndFlags`) followed
by up to 20 callback slots (`initialise`, `release`, `init`, `update`, `hitDetect`, `render`, `free`,
`getObjectTypeId`, `getExtraSize`, then object-specific `slotNN` extras). This is the concrete
on-disk form of the wiki's "all functions stubbed" DLLs:

- `src/main/dll/dll_0004_dummy04.c` (DLL 0x004, wiki: "Dummy04 / all functions stubbed") — every
  entry point is a `*_nop` or `*_ret_<constant>` stub, "used to fill a DLL slot with a known no-op
  so the dispatch tables stay valid" (file's own header comment).
- `src/main/dll/dll_003A_dummy3a.c` (DLL 0x03A, wiki: "Dummy3A / all functions stubbed") — same
  pattern (`Dummy3A_render`/`frameEnd`/`frameStart`/`release`/`initialise`, all empty or constant).

### File-naming convention: `dll_XXXX_name.c` is the primary cross-reference

411 files under `src/main/dll/` (658 counting shared/state-struct headers pulled in) follow
`dll_<4-hex-ID>_<name>.c` / `include/main/dll/dll_<4-hex-ID>_<name>.h`, e.g.
`src/main/dll/dll_0122_cctestinfot.c` = DLL 0x122. Matching this literal ID against the wiki table:

- **419 of the wiki's 469 named DLL IDs** have a directly corresponding `dll_<ID>_*.c` file.
- A further **~24 IDs** are implemented as flat `src/main/<name>.c` files that don't carry the
  `dll_XXXX_` prefix (mostly core engine systems, or files that bundle several adjacent DLL IDs'
  `ObjectDescriptor`s together):
  - DLL 0x002 (`ObjSeq`) → `src/main/objseq.c`; DLL 0x005 (`Sky`) → `src/main/sky.c`.
  - DLL 0x239 (`TextBlock`) → `src/main/textblock.c`; 0x23A (`Platform1`) → `src/main/platform1.c`;
    0x23B (`DFP_Lightni`) → `src/main/dfplightni.c`; 0x23C (`DFP_PowerSl`) → `src/main/dfppowersl.c`.
  - DLL 0x1D2/0x1D3/0x1D4 (`WORLDplanet`/`WorldMapObj`/`WORLDAstero`) →
    `src/main/worldplanet.c` / `worldobj.c` / `worldasteroids.c` (`gWorldPlanetObjDescriptor` etc.,
    `gResourceDescriptors[0x1D2..0x1D4]`).
  - DLL 0x25C/0x25D/0x25E (`SnowClaw`/`CRCloudRace`/`FireSpellStone`) →
    `src/main/snowclaw.c` / `crcloudrace.c` / `spellstone.c`.
  - DLL 0x25F/0x260 (`CRFuelTank`/`ProximityMine`) → both descriptors (`gCrFuelTankObjDescriptor`,
    `gProximityMineObjDescriptor`) are defined together in `src/main/crfueltank.c`.
  - DLL 0x21E-0x223 and 0x225-0x228 (the `VFP_Block1`/`VFP_Platfor`/`VFP_DoorSwi`/`SeqPoint`/
    `VFPDragHead`/`VFP_corepla`/`VFP_flamepo`/`VFP_lavapoo`/`VFP_lavasta`/`VFP_SpellPl` row of the
    wiki table) are ten separate `ObjectDescriptor`s (`gVFP_Block1ObjDescriptor`,
    `VFPDragHead_*`, `VFP_coreplat_*`, ...) all defined in the single file `src/main/light.c` —
    the Volcano Force Point Temple's small placeable-prop objects were apparently one retail
    translation unit.
- **26 wiki IDs have no matching file or named descriptor at all** — in `gResourceDescriptors[]`
  they still point at a literal shared placeholder blob (`{0xffffffff, 0, 0, ..., 0}`, a 12-word
  stub with no real `acquire`/callback pointers), the same pattern used for other genuinely-inert
  slots. Checked one-by-one, **every one of these 26 IDs is also the ones with a blank Description
  column** in the wiki table above (`0x146`, `0x14D`, `0x151`, `0x152`, `0x15C`, `0x161`, `0x165`,
  `0x168`, `0x176`, `0x17C`, `0x205`, `0x208`, `0x213`, `0x214`, `0x23D`, `0x24C`, `0x26A`, `0x26D`,
  `0x270`, `0x274`, `0x275`, `0x277`, `0x278`, `0x27A`, `0x27B`, `0x27F`) — i.e. the wiki's
  lowest-confidence guesses (no observed behaviour to describe) line up exactly with DLL slots this
  binary never gives real behaviour to. That's a genuine (if modest) confirmation that these 26 are
  unused/reserved IDs in the GameCube release, not just "not yet decompiled here."

### Level-prefix legend (from source comments, not the wiki page)

The wiki's 2-4-letter object-name prefixes correspond to real level names; our header/file comments
spell several of these out explicitly where the wiki page doesn't:

| Prefix | Level | Verified in |
|--------|-------|-------------|
| `CC` | Crystal Caves | `src/main/dll/CC/dll_0122_cctestinfot.c` |
| `CF` | CloudRunner Fortress | `src/main/dll/CF/dll_012A_cfcrate.c` |
| `DF` | DragonRock (rope/cradle machinery) | `src/main/dll/DF/dll_0175_dfropenode.c` |
| `DFP` | DragonRock Palace (spell-puzzle level) | `src/main/dll/DF/dll_0229_dfplevelcontrol.c` |
| `DFSH` | DragonRock Shrine (a Krazoa-spirit shrine) | `src/main/dll/DF/dll_0178_dfshshrine.c` |
| `DIM`/`DIM2` | DarkIce Mines (+ boss area) | `src/main/dll/DIM/dll_01BE_dimlava.c` |
| `GPSH` | a Krazoa-spirit shrine (area code not decoded) | `src/main/dll/dll_0192_gpshshrine.c` |
| `MMP` | Moon Mountain Pass | `src/main/dll/MMP/dll_010F_mmpbridge.c` |
| `MMSH` | Moon Mountain Pass Shrine (Krazoa spirit) | `src/main/dll/dll_018C_mmshshrine.c` |
| `ECSH` | a Krazoa-spirit shrine (area code "EC" not decoded — comment notes the MMSH/ECSH/DFSH/DBSH/GPSH family explicitly) | `src/main/dll/dll_018F_ecshshrine.c` |
| `NW` | SnowHorn Wastes (map `nwastes`) | `src/main/dll/NW/dll_0198_nwshlevcon.c` |
| `SH` | SnowHorn / ThornTail Hollow | `src/main/dll/SH/dll_01AE_shlevelcontrol.c` |
| `SB` | ShipBattle (the prologue) | `src/main/dll/SB/dll_01E8_sbgalleon.c` |
| `SC` | LightFoot Village (map `swapcircle`) | `src/main/dll/SC/dll_01B6_sclevelcontrol.c` |
| `VF`/`VFP` | Volcano Force Point Temple | `src/main/dll/VF/dll_0216_vfplevelcontrol.c` |
| `WC` | Walled City | `src/main/dll/WC/dll_028A_wcearthwalker.c` |
| `WM` | Krazoa Palace | `src/main/dll/WM/dll_0209_wmlevelcontrol.c` (comment states this explicitly) |
| `KT` | (torches shared across) KrazoaPalace / ThornTail | `src/main/dll/DR/dll_0128_kttorch.c` |
| `ARW` | Arwing space-combat sections | `src/main/dll/ARW/dll_029A_arwarwing.c` |

### The `_DLL_ID` convention

15 headers define a local `#define <NAME>_DLL_ID 0xNNNN` next to the struct(s) that need to check
their own ID at runtime (e.g. `include/main/textblock.h:6` → `TEXTBLOCK_DLL_ID 0x0239`,
`include/main/dfppowersl.h:12` → `DFPPOWERSL_DLL_ID 0x023C`). This is deliberately per-file, not
centralized — it lines up with the `dll_XXXX_name.c` filename convention as the source of truth for
"which file is DLL N", rather than a single project-wide enum.

## Ready-to-adopt code

Nothing here needs a new enum/struct in the general case — the `dll_XXXX_name.c` filename
convention already encodes the ID↔implementation mapping for 419/469 wiki entries, and the
per-file `_DLL_ID` `#define` convention (above) covers the cases that need a named constant. The one
piece of knowledge from this cross-reference that isn't recorded anywhere in-tree yet is *which*
DLL IDs are confirmed-inert (stub descriptor, blank wiki description, no source file) — worth a
one-line marker if a maintainer later adds a canonical DLL ID listing:

```c
/* DLL IDs whose gResourceDescriptors[] slot is still the shared null/stub descriptor
 * ({0xffffffff, 0, ...}, no acquire/callback pointers) as of this cross-reference —
 * i.e. confirmed unused/reserved in the GC retail build, not merely undecompiled.
 * (Source: docs/wiki/DLLs.md "In this codebase" section.) */
#define SFA_DLL_UNUSED_IDS \
    0x146, 0x14D, 0x151, 0x152, 0x15C, 0x161, 0x165, 0x168, 0x176, 0x17C, \
    0x205, 0x208, 0x213, 0x214, 0x23D, 0x24C, 0x26A, 0x26D, 0x270, 0x274, \
    0x275, 0x277, 0x278, 0x27A, 0x27B, 0x27F
```
