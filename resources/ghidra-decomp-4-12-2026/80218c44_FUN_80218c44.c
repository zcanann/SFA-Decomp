// Function: FUN_80218c44
// Entry: 80218c44
// Size: 1012 bytes

/* WARNING: Removing unreachable block (ram,0x80219014) */
/* WARNING: Removing unreachable block (ram,0x80218c8c) */
/* WARNING: Removing unreachable block (ram,0x80218c54) */

void FUN_80218c44(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  byte bVar4;
  uint uVar5;
  int iVar6;
  byte bVar7;
  uint *puVar8;
  double dVar9;
  int local_48;
  float afStack_44 [3];
  float afStack_38 [7];
  
  puVar8 = *(uint **)(param_9 + 0x5c);
  bVar1 = false;
  bVar7 = *(byte *)(puVar8 + 1);
  if (bVar7 == 2) {
    *(undefined *)(param_9 + 0x1b) = 0;
    if (puVar8[2] == 0) {
      FUN_80035ff8((int)param_9);
    }
    puVar8[2] = puVar8[2] + (uint)DAT_803dc070;
    if (0x80 < (int)puVar8[2]) {
      FUN_80035ff8((int)param_9);
      FUN_8000b844((int)param_9,0x173);
      FUN_8000b844((int)param_9,0x3c5);
      *(undefined *)(puVar8 + 1) = 1;
    }
  }
  else if (bVar7 < 2) {
    if (bVar7 != 0) {
      dVar9 = (double)((float)puVar8[3] + FLOAT_803dc074);
      puVar8[3] = (uint)((float)puVar8[3] + FLOAT_803dc074);
      if ((double)FLOAT_803e7600 < dVar9) {
        FUN_8002cc9c(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
        return;
      }
    }
  }
  else if (bVar7 == 4) {
    iVar3 = FUN_8002bac4();
    dVar9 = (double)FLOAT_803e75f4;
    if ((((double)*(float *)(iVar3 + 0x24) != dVar9) || ((double)*(float *)(iVar3 + 0x28) != dVar9))
       || ((double)*(float *)(iVar3 + 0x2c) != dVar9)) {
      dVar9 = FUN_80247f54((float *)(iVar3 + 0x24));
    }
    dVar9 = (double)(float)((double)FLOAT_803dcf20 + dVar9);
    FUN_80222268(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,
                 (float *)(param_9 + 6),afStack_38);
    FUN_80247eb8(afStack_38,(float *)(param_9 + 6),afStack_44);
    FUN_80247ef8(afStack_44,afStack_44);
    FUN_80247edc((double)(float)(dVar9 * (double)FLOAT_803dcf1c),afStack_44,afStack_44);
    FUN_80247edc((double)FLOAT_803dcf18,(float *)(param_9 + 0x12),(float *)(param_9 + 0x12));
    FUN_80247e94((float *)(param_9 + 0x12),afStack_44,(float *)(param_9 + 0x12));
    FUN_80293900((double)(*(float *)(param_9 + 0x12) * *(float *)(param_9 + 0x12) +
                         *(float *)(param_9 + 0x16) * *(float *)(param_9 + 0x16)));
    iVar3 = FUN_80021884();
    *param_9 = (short)iVar3;
    iVar3 = FUN_80021884();
    param_9[1] = (short)iVar3;
    param_2 = (double)(*(float *)(param_9 + 0x14) * FLOAT_803dc074);
    param_3 = (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074);
    FUN_8002ba34((double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074),param_2,param_3,(int)param_9)
    ;
    bVar1 = true;
  }
  else if (bVar7 < 4) {
    bVar1 = true;
    param_2 = (double)(*(float *)(param_9 + 0x14) * FLOAT_803dc074);
    param_3 = (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074);
    FUN_8002ba34((double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074),param_2,param_3,(int)param_9)
    ;
  }
  if (bVar1) {
    iVar6 = *(int *)(*(int *)(param_9 + 0x2a) + 0x50);
    local_48 = 0;
    iVar3 = FUN_80036974((int)param_9,&local_48,(int *)0x0,(uint *)0x0);
    bVar7 = 0;
    uVar5 = (uint)DAT_803dc070;
    uVar2 = puVar8[2];
    puVar8[2] = uVar2 - uVar5;
    if (((int)(uVar2 - uVar5) < 0) || (iVar3 != 0)) {
      bVar7 = 1;
    }
    bVar4 = 0;
    if ((iVar6 != 0) && (*(short *)(iVar6 + 0x46) != 0x2ab)) {
      bVar4 = 1;
    }
    bVar7 = bVar7 | bVar4 | *(byte *)(*(int *)(param_9 + 0x2a) + 0xad);
    if (*(char *)(puVar8 + 1) == '\x04') {
      iVar3 = FUN_8002bac4();
      dVar9 = (double)FUN_800217c8((float *)(param_9 + 0xc),(float *)(iVar3 + 0x18));
      if (dVar9 < (double)FLOAT_803dcf24) {
        bVar7 = bVar7 | 1;
      }
    }
    if ((local_48 != 0) && (*(short *)(local_48 + 0x46) == 0x2ab)) {
      bVar7 = 0;
    }
    if (bVar7 != 0) {
      *(undefined *)(puVar8 + 1) = 2;
      puVar8[2] = 0;
      if ((*(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & 8) != 0) {
        FUN_8000bb38((uint)param_9,0x172);
      }
      if (*(char *)(param_9 + 0x56) == '\x02') {
        FUN_8009adfc((double)FLOAT_803e75d8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,3,0,0,0,0,0,3);
      }
      else {
        FUN_8009adfc((double)FLOAT_803e75d8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,1,0,0,0,0,0,3);
      }
      if (*puVar8 != 0) {
        FUN_8001f448(*puVar8);
        *puVar8 = 0;
      }
    }
    *(undefined4 *)(*(int *)(param_9 + 0x2a) + 0x4c) = 0x10;
    *(undefined4 *)(*(int *)(param_9 + 0x2a) + 0x48) = 0x10;
  }
  if ((*puVar8 != 0) && (iVar3 = FUN_8001dc28(*puVar8), iVar3 != 0)) {
    FUN_8001d774(*puVar8);
  }
  return;
}

