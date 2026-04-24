// Function: FUN_80207ce4
// Entry: 80207ce4
// Size: 728 bytes

void FUN_80207ce4(void)

{
  int iVar1;
  int iVar2;
  char cVar4;
  short sVar3;
  short sVar5;
  short *psVar6;
  int *piVar7;
  int local_28 [10];
  
  iVar1 = FUN_802860dc();
  psVar6 = *(short **)(iVar1 + 0xb8);
  if (((*(byte *)(psVar6 + 4) >> 5 & 1) == 0) && (iVar2 = FUN_8001ffb4((int)*psVar6), iVar2 == 0)) {
    if (*(char *)((int)psVar6 + 7) == '\x04') {
      FUN_8000bb18(0,0x7e);
      *(byte *)(psVar6 + 4) = *(byte *)(psVar6 + 4) & 0xdf | 0x20;
      *(byte *)(psVar6 + 4) = *(byte *)(psVar6 + 4) & 0xef;
      *(byte *)(psVar6 + 4) = *(byte *)(psVar6 + 4) & 0xbf;
      FUN_800200e8((int)*psVar6,1);
      FUN_800200e8(0xedf,0);
      cVar4 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(iVar1 + 0xac));
      if (cVar4 == '\x01') {
        FUN_800200e8(0x9f7,1);
      }
      FUN_8001467c();
    }
    else {
      if ((char)*(byte *)(psVar6 + 4) < '\0') {
        *(byte *)(psVar6 + 4) = *(byte *)(psVar6 + 4) & 0x7f;
        if ((*(byte *)(psVar6 + 4) >> 4 & 1) != 0) {
          cVar4 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(iVar1 + 0xac));
          if (cVar4 == '\x01') {
            FUN_800146bc(0x1d,0x96);
          }
          else {
            FUN_800146bc(0x1d,0xb4);
          }
          FUN_8001469c();
        }
      }
      iVar2 = FUN_80014670();
      if (iVar2 != 0) {
        piVar7 = &DAT_803ad138;
        for (sVar5 = 0; sVar5 < 4; sVar5 = sVar5 + 1) {
          if (*piVar7 != 0) {
            FUN_8002cbc4();
          }
          *piVar7 = 0;
          if (piVar7[1] != 0) {
            FUN_8002cbc4();
          }
          piVar7[1] = 0;
          FUN_8000bb18(iVar1,0x1ce);
          piVar7 = piVar7 + 2;
        }
        *(undefined *)((int)psVar6 + 7) = 0;
        *(byte *)(psVar6 + 4) = *(byte *)(psVar6 + 4) & 0xbf;
        *(byte *)(psVar6 + 4) = *(byte *)(psVar6 + 4) & 0xef;
        FUN_800200e8(0xedf,0);
      }
      FUN_8020768c(iVar1);
      piVar7 = &DAT_803ad138;
      for (sVar5 = 0; sVar5 < 4; sVar5 = sVar5 + 1) {
        if (*piVar7 != 0) {
          local_28[0] = 0;
          sVar3 = FUN_8003687c(piVar7[1],local_28,0,0);
          if ((sVar3 == 0x13) &&
             ((cVar4 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(iVar1 + 0xac)),
              cVar4 == '\x01' || (*(int *)(local_28[0] + 0xf4) == (int)sVar5)))) {
            if (*piVar7 != 0) {
              FUN_8002cbc4();
            }
            *piVar7 = 0;
            if (piVar7[1] != 0) {
              FUN_8002cbc4();
            }
            piVar7[1] = 0;
            FUN_8000bb18(0,0x409);
            *(char *)((int)psVar6 + 7) = *(char *)((int)psVar6 + 7) + '\x01';
          }
        }
        piVar7 = piVar7 + 2;
      }
    }
  }
  FUN_80286128();
  return;
}

