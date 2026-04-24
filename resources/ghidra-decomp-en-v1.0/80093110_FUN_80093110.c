// Function: FUN_80093110
// Entry: 80093110
// Size: 2324 bytes

/* WARNING: Removing unreachable block (ram,0x800932e0) */

void FUN_80093110(undefined2 *param_1,int param_2,int param_3)

{
  byte bVar1;
  char cVar2;
  ushort uVar3;
  double dVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  undefined2 local_44;
  undefined2 local_42;
  undefined2 local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  double local_28;
  double local_20;
  double local_18;
  
  local_50 = DAT_802c1fa8;
  local_4c = DAT_802c1fac;
  local_48 = DAT_802c1fb0;
  local_5c = DAT_802c1fb4;
  local_58 = DAT_802c1fb8;
  local_54 = DAT_802c1fbc;
  iVar5 = FUN_800e84f8();
  if (param_3 != 0) {
    if (param_1 != (undefined2 *)0x0) {
      local_50 = *(float *)(param_1 + 0xc);
      local_4c = *(float *)(param_1 + 0xe);
      local_48 = *(float *)(param_1 + 0x10);
    }
    if (param_2 != 0) {
      local_5c = *(float *)(param_2 + 0x18);
      local_58 = *(float *)(param_2 + 0x1c);
      local_54 = *(float *)(param_2 + 0x20);
    }
    uVar6 = (uint)*(ushort *)(param_3 + 0x26);
    if (uVar6 < 9) {
      iVar7 = (&DAT_8039a828)[uVar6];
      if (iVar7 != 0) {
        if ((iVar7 != 0) && (bVar1 = *(byte *)(param_3 + 0x58), (bVar1 & 2) == 0)) {
          if (((bVar1 & 8) == 0) || (*(char *)(iVar7 + 0x144e) == '\0')) {
            if ((bVar1 & 0x20) == 0) {
              if ((bVar1 & 4) != 0) {
                if (*(char *)(iVar7 + 0x144f) != '\0') {
                  *(undefined *)(iVar7 + 0x144f) = 0;
                }
                *(int *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)] + 0x13f8) =
                     1 - *(int *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)] + 0x13f8);
                if (*(ushort *)(param_3 + 0x2a) == 0) {
                  local_18 = (double)CONCAT44(0x43300000,
                                              *(int *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)]
                                                      + 0x13fc) - 1U ^ 0x80000000);
                  *(float *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)] + 0x142c) =
                       (float)(local_18 - DOUBLE_803df1a8);
                }
                else {
                  local_18 = (double)CONCAT44(0x43300000,
                                              *(uint *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)]
                                                       + 0x13fc) ^ 0x80000000);
                  local_20 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(param_3 + 0x2a));
                  *(float *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)] + 0x142c) =
                       (float)(local_18 - DOUBLE_803df1a8) / (float)(local_20 - DOUBLE_803df1b0);
                }
                if (*(ushort *)(param_3 + 0x2c) == 0) {
                  local_18 = (double)CONCAT44(0x43300000,
                                              -(*(int *)((&DAT_8039a828)
                                                         [*(ushort *)(param_3 + 0x26)] + 0x13fc) +
                                               -1) ^ 0x80000000);
                  *(float *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)] + 0x1430) =
                       (float)(local_18 - DOUBLE_803df1a8);
                }
                else {
                  local_18 = (double)CONCAT44(0x43300000,
                                              *(uint *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)]
                                                       + 0x13fc) ^ 0x80000000);
                  local_20 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(param_3 + 0x2c));
                  *(float *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)] + 0x1430) =
                       -((float)(local_18 - DOUBLE_803df1a8) / (float)(local_20 - DOUBLE_803df1b0));
                }
              }
            }
            else {
              FUN_80092e64(uVar6,0);
            }
          }
          else {
            *(undefined *)(iVar5 + uVar6 + 0x41) = *(undefined *)(iVar7 + 0x144d);
            *(char *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)] + 0x144d) =
                 '\x01' - *(char *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)] + 0x144d);
            iVar7 = (&DAT_8039a828)[*(ushort *)(param_3 + 0x26)];
            if (*(char *)(iVar7 + 0x144d) == '\x01') {
              local_68 = FLOAT_803df1a0;
              local_64 = FLOAT_803df1a0;
              local_60 = FLOAT_803df1a0;
              local_38 = FLOAT_803df1a0;
              local_34 = FLOAT_803df1a0;
              local_30 = FLOAT_803df1a0;
              local_3c = FLOAT_803df1a4;
              local_40 = 0;
              local_42 = 0;
              local_44 = *param_1;
              FUN_80021ac8(&local_44,&local_68);
              *(float *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)] + 0x140c) =
                   local_68 + *(float *)(param_1 + 0xc);
              *(float *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)] + 0x1410) =
                   local_64 + *(float *)(param_1 + 0xe);
              *(float *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)] + 0x1414) =
                   local_60 + *(float *)(param_1 + 0x10);
              if (FLOAT_803df27c < *(float *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)] + 0x1438)
                 ) {
                FUN_8000a518(*(undefined4 *)
                              (&DAT_8030f5a0 +
                              *(int *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)] + 0x13f4) * 4),0
                            );
              }
            }
            else if (FLOAT_803df27c < *(float *)(iVar7 + 0x1438)) {
              FUN_8000a518(*(undefined4 *)(&DAT_8030f5a0 + *(int *)(iVar7 + 0x13f4) * 4),1);
            }
            if (*(char *)(iVar5 + (uint)*(ushort *)(param_3 + 0x26) + 0x41) == '\0') {
              *(int *)(iVar5 + (uint)*(ushort *)(param_3 + 0x26) * 0xc + 0x14) = (int)local_50;
              *(int *)(iVar5 + (uint)*(ushort *)(param_3 + 0x26) * 0xc + 0x18) = (int)local_4c;
              *(int *)(iVar5 + (uint)*(ushort *)(param_3 + 0x26) * 0xc + 0x1c) = (int)local_48;
            }
          }
        }
      }
      else {
        bVar1 = *(byte *)(param_3 + 0x58);
        if ((((bVar1 & 4) == 0) && ((bVar1 & 8) == 0)) && ((bVar1 & 0x20) == 0)) {
          if ((((bVar1 & 2) == 0) || ((bVar1 & 0x10) == 0)) || (*(char *)(param_3 + 0x5d) == '\0'))
          {
            if (((bVar1 & 2) == 0) || ((bVar1 & 0x10) == 0)) {
              if ((bVar1 & 2) != 0) {
                FUN_800919c8((double)local_50,(double)local_4c,(double)local_48,param_3,param_2);
              }
            }
            else {
              FUN_800919c8((double)local_5c,(double)local_58,(double)local_54,param_3,param_2);
            }
          }
          else {
            FUN_800919c8((double)local_50,(double)local_4c,(double)local_48,param_3,param_2);
          }
        }
        if (((*(byte *)(param_3 + 0x58) & 2) != 0) &&
           ((*(char *)(param_3 + 0x5c) == '\0' || (*(char *)(param_3 + 0x5c) == '\x04')))) {
          uVar3 = *(ushort *)(param_3 + 0x26);
          if (uVar3 == 1) {
            *(short *)(iVar5 + 0x10) = *(short *)(param_3 + 0x24) + -1;
            *(int *)(iVar5 + 0x20) = (int)local_50;
            *(int *)(iVar5 + 0x24) = (int)local_4c;
            *(int *)(iVar5 + 0x28) = (int)local_48;
            cVar2 = *(char *)(iVar5 + (uint)*(ushort *)(param_3 + 0x26) + 0x41);
            if (cVar2 != -1) {
              *(char *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)] + 0x144d) = '\x01' - cVar2;
              dVar4 = DOUBLE_803df1a8;
              uVar6 = (uint)*(ushort *)(param_3 + 0x26);
              if (*(char *)(iVar5 + uVar6 + 0x41) == '\0') {
                local_18 = (double)CONCAT44(0x43300000,
                                            *(uint *)(iVar5 + uVar6 * 0xc + 0x14) ^ 0x80000000);
                *(float *)((&DAT_8039a828)[uVar6] + 0x140c) = (float)(local_18 - DOUBLE_803df1a8);
                local_20 = (double)CONCAT44(0x43300000,
                                            *(uint *)(iVar5 + (uint)*(ushort *)(param_3 + 0x26) *
                                                              0xc + 0x18) ^ 0x80000000);
                *(float *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)] + 0x1410) =
                     (float)(local_20 - dVar4);
                local_28 = (double)CONCAT44(0x43300000,
                                            *(uint *)(iVar5 + (uint)*(ushort *)(param_3 + 0x26) *
                                                              0xc + 0x1c) ^ 0x80000000);
                *(float *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)] + 0x1414) =
                     (float)(local_28 - dVar4);
              }
            }
          }
          else if (uVar3 == 0) {
            *(short *)(iVar5 + 0xe) = *(short *)(param_3 + 0x24) + -1;
            *(int *)(iVar5 + 0x14) = (int)local_50;
            *(int *)(iVar5 + 0x18) = (int)local_4c;
            *(int *)(iVar5 + 0x1c) = (int)local_48;
            cVar2 = *(char *)(iVar5 + (uint)*(ushort *)(param_3 + 0x26) + 0x41);
            if (cVar2 != -1) {
              *(char *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)] + 0x144d) = '\x01' - cVar2;
              dVar4 = DOUBLE_803df1a8;
              uVar6 = (uint)*(ushort *)(param_3 + 0x26);
              if (*(char *)(iVar5 + uVar6 + 0x41) == '\0') {
                local_18 = (double)CONCAT44(0x43300000,
                                            *(uint *)(iVar5 + uVar6 * 0xc + 0x14) ^ 0x80000000);
                *(float *)((&DAT_8039a828)[uVar6] + 0x140c) = (float)(local_18 - DOUBLE_803df1a8);
                local_20 = (double)CONCAT44(0x43300000,
                                            *(uint *)(iVar5 + (uint)*(ushort *)(param_3 + 0x26) *
                                                              0xc + 0x18) ^ 0x80000000);
                *(float *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)] + 0x1410) =
                     (float)(local_20 - dVar4);
                local_28 = (double)CONCAT44(0x43300000,
                                            *(uint *)(iVar5 + (uint)*(ushort *)(param_3 + 0x26) *
                                                              0xc + 0x1c) ^ 0x80000000);
                *(float *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)] + 0x1414) =
                     (float)(local_28 - dVar4);
              }
            }
          }
          else if (uVar3 < 3) {
            *(short *)(iVar5 + 0x12) = *(short *)(param_3 + 0x24) + -1;
            *(int *)(iVar5 + 0x2c) = (int)local_50;
            *(int *)(iVar5 + 0x30) = (int)local_4c;
            *(int *)(iVar5 + 0x34) = (int)local_48;
            cVar2 = *(char *)(iVar5 + (uint)*(ushort *)(param_3 + 0x26) + 0x41);
            if (cVar2 != -1) {
              *(char *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)] + 0x144d) = '\x01' - cVar2;
              dVar4 = DOUBLE_803df1a8;
              uVar6 = (uint)*(ushort *)(param_3 + 0x26);
              if (*(char *)(iVar5 + uVar6 + 0x41) == '\0') {
                local_18 = (double)CONCAT44(0x43300000,
                                            *(uint *)(iVar5 + uVar6 * 0xc + 0x14) ^ 0x80000000);
                *(float *)((&DAT_8039a828)[uVar6] + 0x140c) = (float)(local_18 - DOUBLE_803df1a8);
                local_20 = (double)CONCAT44(0x43300000,
                                            *(uint *)(iVar5 + (uint)*(ushort *)(param_3 + 0x26) *
                                                              0xc + 0x18) ^ 0x80000000);
                *(float *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)] + 0x1410) =
                     (float)(local_20 - dVar4);
                local_28 = (double)CONCAT44(0x43300000,
                                            *(uint *)(iVar5 + (uint)*(ushort *)(param_3 + 0x26) *
                                                              0xc + 0x1c) ^ 0x80000000);
                *(float *)((&DAT_8039a828)[*(ushort *)(param_3 + 0x26)] + 0x1414) =
                     (float)(local_28 - dVar4);
              }
            }
          }
        }
      }
    }
  }
  return;
}

