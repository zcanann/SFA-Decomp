// Function: FUN_8020ad98
// Entry: 8020ad98
// Size: 888 bytes

/* WARNING: Removing unreachable block (ram,0x8020b0f0) */
/* WARNING: Removing unreachable block (ram,0x8020ada8) */

void FUN_8020ad98(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  undefined2 *puVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  float *pfVar9;
  undefined8 extraout_f1;
  double dVar10;
  double dVar11;
  double in_f31;
  double dVar12;
  double in_ps31_1;
  undefined8 uVar13;
  float local_88;
  float local_84;
  float local_80;
  float afStack_7c [3];
  float afStack_70 [3];
  float local_64;
  float local_60;
  float local_5c;
  longlong local_58;
  longlong local_50;
  undefined4 local_48;
  uint uStack_44;
  undefined8 local_40;
  undefined8 local_38;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar13 = FUN_8028683c();
  uVar2 = (uint)((ulonglong)uVar13 >> 0x20);
  iVar8 = (int)uVar13;
  if ((-1 < param_11) && (param_11 < 4)) {
    if (param_11 == 2) {
      if (((*(byte *)(iVar8 + 0x198) >> 6 & 1) == 0) &&
         (uVar13 = extraout_f1, uVar4 = FUN_8002e144(), (uVar4 & 0xff) != 0)) {
        puVar5 = FUN_8002becc(0x24,0x709);
        *(undefined *)(puVar5 + 2) = 2;
        *(undefined *)((int)puVar5 + 5) = 1;
        *(undefined *)(puVar5 + 3) = 0xff;
        *(undefined *)((int)puVar5 + 7) = 0xff;
        *(undefined4 *)(puVar5 + 4) = *(undefined4 *)(iVar8 + 0x1c);
        *(undefined4 *)(puVar5 + 6) = *(undefined4 *)(iVar8 + 0x20);
        *(undefined4 *)(puVar5 + 8) = *(undefined4 *)(iVar8 + 0x24);
        puVar5[0xd] = 0x3c;
        local_38 = (double)(longlong)(int)FLOAT_803dcdfc;
        puVar5[0xe] = (short)(int)FLOAT_803dcdfc;
        local_40 = (double)(longlong)(int)FLOAT_803dcdf8;
        *(char *)((int)puVar5 + 0x19) = (char)(int)FLOAT_803dcdf8;
        FUN_8002b678(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar2,puVar5);
        FUN_8000bb38(uVar2,0x477);
      }
    }
    else if ((((param_11 < 2) && (0 < param_11)) &&
             (uVar13 = extraout_f1, iVar3 = FUN_8002bac4(), (*(byte *)(iVar8 + 0x198) >> 6 & 1) != 0
             )) && (uVar4 = FUN_8002e144(), (uVar4 & 0xff) != 0)) {
      puVar5 = FUN_8002becc(0x20,0x70f);
      *(undefined4 *)(puVar5 + 4) = *(undefined4 *)(iVar8 + 0x1c);
      *(undefined4 *)(puVar5 + 6) = *(undefined4 *)(iVar8 + 0x20);
      *(undefined4 *)(puVar5 + 8) = *(undefined4 *)(iVar8 + 0x24);
      *(undefined *)(puVar5 + 2) = 1;
      *(undefined *)((int)puVar5 + 5) = 1;
      *(undefined *)(puVar5 + 3) = 0xff;
      *(undefined *)((int)puVar5 + 7) = 0xff;
      if ((iVar3 != 0) &&
         (uVar4 = FUN_8002b678(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar2,
                               puVar5), uVar4 != 0)) {
        dVar10 = (double)FUN_800217c8((float *)(uVar2 + 0x18),(float *)(iVar3 + 0x18));
        uVar7 = (uint)-(float)((double)FLOAT_803dcdf0 * dVar10);
        local_58 = (longlong)(int)uVar7;
        uVar1 = (uint)((double)FLOAT_803dcdf0 * dVar10);
        local_50 = (longlong)(int)uVar1;
        uStack_44 = FUN_80022264(uVar7,uVar1);
        uStack_44 = uStack_44 ^ 0x80000000;
        local_48 = 0x43300000;
        local_64 = *(float *)(iVar3 + 0xc) +
                   (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e71c0);
        uVar6 = FUN_80022264(uVar7,uVar1);
        local_40 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        local_60 = *(float *)(iVar3 + 0x10) + (float)(local_40 - DOUBLE_803e71c0);
        uVar7 = FUN_80022264(uVar7,uVar1);
        local_38 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_5c = *(float *)(iVar3 + 0x14) + (float)(local_38 - DOUBLE_803e71c0);
        FUN_80247eb8((float *)(iVar3 + 0xc),(float *)(iVar8 + 0x1c),afStack_70);
        FUN_80247eb8(&local_64,(float *)(iVar8 + 0x1c),afStack_7c);
        FUN_80247ef8(afStack_70,afStack_70);
        dVar10 = FUN_80247f90((float *)(iVar3 + 0x24),afStack_70);
        dVar11 = (double)*(float *)(iVar8 + 0x188);
        dVar12 = (double)(float)(dVar11 * dVar10 + (double)*(float *)(iVar8 + 0x184));
        FUN_80247edc(dVar12,afStack_70,(float *)(uVar4 + 0x24));
        pfVar9 = *(float **)(uVar4 + 0xb8);
        dVar10 = FUN_80247f90(afStack_70,afStack_7c);
        FUN_80247edc(dVar10,afStack_70,&local_88);
        FUN_80247eb8(afStack_7c,&local_88,&local_88);
        if ((local_88 != FLOAT_803e71a8) ||
           ((local_84 != FLOAT_803e71a8 || (local_80 != FLOAT_803e71a8)))) {
          FUN_80247ef8(&local_88,&local_88);
        }
        uVar13 = FUN_80247edc((double)(*(float *)(iVar8 + 0x184) * FLOAT_803dcdf4),&local_88,
                              (float *)(uVar4 + 0x24));
        *pfVar9 = (float)dVar12;
        FUN_802185f8(uVar13,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,uVar4);
        FUN_800803f8((undefined4 *)(iVar8 + 0x18));
        FUN_80080404((float *)(iVar8 + 0x18),0x1e);
        FUN_8000bb38(uVar2,0x477);
        FUN_8000bb38(uVar2,0x3c8);
      }
    }
  }
  FUN_80286888();
  return;
}

