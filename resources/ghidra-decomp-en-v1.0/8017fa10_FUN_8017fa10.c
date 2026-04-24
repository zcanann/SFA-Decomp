// Function: FUN_8017fa10
// Entry: 8017fa10
// Size: 884 bytes

void FUN_8017fa10(int param_1)

{
  float fVar1;
  char cVar2;
  float fVar3;
  int iVar4;
  undefined2 uVar5;
  int iVar6;
  uint uVar7;
  int *piVar8;
  double dVar9;
  undefined auStack72 [4];
  undefined auStack68 [4];
  undefined auStack64 [4];
  undefined auStack60 [12];
  float local_30;
  undefined auStack44 [4];
  float local_28 [2];
  undefined4 local_20;
  uint uStack28;
  
  iVar6 = *(int *)(param_1 + 0x4c);
  piVar8 = *(int **)(param_1 + 0xb8);
  if ((*piVar8 == 0) || (*(char *)(param_1 + 0xeb) != '\0')) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    iVar4 = FUN_8002b044(param_1);
    if (iVar4 == 0) {
      cVar2 = *(char *)((int)piVar8 + 0xf);
      if (cVar2 == '\x02') {
        if (FLOAT_803e3858 <= *(float *)(param_1 + 0x98)) {
          iVar6 = (uint)*(byte *)(param_1 + 0x36) + (uint)DAT_803db410 * -2;
          if (iVar6 < 0) {
            iVar6 = 0;
            *(undefined *)((int)piVar8 + 0xf) = 3;
            fVar1 = FLOAT_803e385c;
            piVar8[1] = (int)FLOAT_803e385c;
            piVar8[2] = (int)fVar1;
            FUN_80030334(param_1,0,0);
            FUN_80030304((double)FLOAT_803e385c,param_1);
          }
          *(char *)(param_1 + 0x36) = (char)iVar6;
        }
        *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
             *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
      }
      else if (cVar2 < '\x02') {
        if (cVar2 == '\0') {
          iVar4 = (**(code **)(*DAT_803dcaac + 0x68))(*(undefined4 *)(iVar6 + 0x14));
          if (iVar4 == 0) {
            dVar9 = (double)(**(code **)(*DAT_803dcaac + 0x6c))(*(undefined4 *)(iVar6 + 0x14));
            uStack28 = (uint)*(ushort *)(iVar6 + 0x18);
            if (uStack28 < 100) {
              uStack28 = 100;
            }
            uStack28 = uStack28 ^ 0x80000000;
            local_20 = 0x43300000;
            fVar1 = (float)(dVar9 / (double)(float)((double)CONCAT44(0x43300000,uStack28) -
                                                   DOUBLE_803e3860));
            fVar3 = FLOAT_803e3858;
            if ((fVar1 <= FLOAT_803e3858) && (fVar3 = fVar1, fVar1 < FLOAT_803e385c)) {
              fVar3 = FLOAT_803e385c;
            }
            piVar8[1] = (int)(FLOAT_803e3858 - fVar3);
          }
          else {
            FUN_8017f7b8(param_1,(int)*(short *)(&DAT_803dbd98 + (*(byte *)(iVar6 + 0x1b) & 3) * 2))
            ;
            *(undefined *)((int)piVar8 + 0xf) = 1;
            uVar5 = FUN_800221a0(300,600);
            *(undefined2 *)(piVar8 + 3) = uVar5;
          }
          if (*(short *)(param_1 + 0xa0) != 0) {
            FUN_80030334((double)(float)piVar8[1],param_1,0,0);
          }
          FUN_80030304((double)(float)piVar8[1],param_1);
        }
        else if (-1 < cVar2) {
          FUN_8017f4f4(param_1,iVar6,piVar8);
        }
      }
      else if (cVar2 == '\x04') {
        FUN_8017f334(param_1,iVar6,piVar8);
      }
      else if (cVar2 < '\x04') {
        uVar7 = (uint)*(byte *)(param_1 + 0x36) + (uint)DAT_803db410;
        if (0xfe < uVar7) {
          uVar7 = 0xff;
          *(undefined *)((int)piVar8 + 0xf) = 0;
          uStack28 = (uint)*(ushort *)(iVar6 + 0x18);
          local_20 = 0x43300000;
          (**(code **)(*DAT_803dcaac + 100))
                    ((double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e3868),
                     *(undefined4 *)(iVar6 + 0x14));
        }
        *(char *)(param_1 + 0x36) = (char)uVar7;
        *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
             *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) | 1;
      }
      FUN_8002fa48((double)(float)piVar8[2],(double)FLOAT_803db414,param_1,0);
    }
    else {
      iVar6 = FUN_80036770(param_1,auStack64,auStack72,auStack68,&local_30,auStack44,local_28);
      if ((iVar6 != 0) && (iVar6 != 0x10)) {
        local_30 = local_30 + FLOAT_803dcdd8;
        local_28[0] = local_28[0] + FLOAT_803dcddc;
        FUN_8009a1dc((double)FLOAT_803e3888,param_1,auStack60,1,0);
        FUN_8000bb18(param_1,0x47b);
        FUN_8002af98(param_1);
      }
    }
  }
  else {
    *piVar8 = 0;
    FUN_8002cbc4();
  }
  return;
}

