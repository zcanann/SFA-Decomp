// Function: FUN_801c1414
// Entry: 801c1414
// Size: 376 bytes

/* WARNING: Removing unreachable block (ram,0x801c156c) */
/* WARNING: Removing unreachable block (ram,0x801c1424) */

void FUN_801c1414(void)

{
  undefined4 *puVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  float *pfVar5;
  float *pfVar6;
  double dVar7;
  double in_f31;
  double dVar8;
  double in_ps31_1;
  float afStack_58 [3];
  float afStack_4c [3];
  float local_40;
  float local_3c;
  float local_38;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  puVar1 = (undefined4 *)FUN_80286840();
  pfVar5 = (float *)*puVar1;
  dVar8 = (double)FLOAT_803e5a94;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(puVar1 + 2); iVar3 = iVar3 + 1) {
    local_38 = (float)dVar8;
    local_3c = (float)dVar8;
    local_40 = (float)dVar8;
    if (*(char *)(pfVar5 + 0xc) == '\0') {
      pfVar6 = pfVar5;
      for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(pfVar5 + 9); iVar4 = iVar4 + 1) {
        fVar2 = pfVar6[10];
        if (pfVar5 == *(float **)((int)fVar2 + 4)) {
          FUN_80247e94(&local_40,(float *)((int)fVar2 + 0x18),&local_40);
        }
        else {
          FUN_80247eb8(&local_40,(float *)((int)fVar2 + 0x18),&local_40);
        }
        pfVar6 = pfVar6 + 1;
      }
      dVar7 = FUN_80247f54(&local_40);
      if ((double)(float)puVar1[0xb] < dVar7) {
        FUN_80247edc((double)(float)((double)(float)puVar1[0xb] / dVar7),&local_40,&local_40);
      }
      FUN_80247edc((double)(float)puVar1[0x10],&local_40,&local_40);
      FUN_80247e94(&local_40,pfVar5 + 6,&local_40);
      FUN_80247e94(pfVar5 + 3,&local_40,pfVar5 + 3);
      FUN_80247edc((double)(float)puVar1[0xe],pfVar5 + 3,afStack_4c);
      FUN_80247eb8(pfVar5 + 3,afStack_4c,pfVar5 + 3);
      pfVar5[4] = (float)puVar1[0xc] * (float)puVar1[0xf] + pfVar5[4];
      FUN_80247edc((double)(float)puVar1[0xc],pfVar5 + 3,afStack_58);
      FUN_80247e94(pfVar5,afStack_58,pfVar5);
    }
    pfVar5 = pfVar5 + 0xd;
  }
  FUN_8028688c();
  return;
}

