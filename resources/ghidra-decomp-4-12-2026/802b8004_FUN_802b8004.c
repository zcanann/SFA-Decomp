// Function: FUN_802b8004
// Entry: 802b8004
// Size: 616 bytes

/* WARNING: Removing unreachable block (ram,0x802b8244) */
/* WARNING: Removing unreachable block (ram,0x802b8014) */

undefined4
FUN_802b8004(undefined8 param_1,short *param_2,int param_3,undefined4 param_4,undefined4 param_5,
            undefined4 param_6,undefined4 param_7,undefined4 param_8,undefined4 param_9)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined8 local_38;
  
  iVar2 = *(int *)(param_2 + 0x5c);
  iVar3 = *(int *)(iVar2 + 0x40c);
  if (*(float *)(iVar3 + 0x14) <= FLOAT_803e8e18) {
    FUN_8000bb38((uint)param_2,0x4be);
    uVar1 = FUN_80022264(0x78,0xb4);
    local_38 = (double)CONCAT44(0x43300000,uVar1 ^ 0x80000000);
    *(float *)(iVar3 + 0x14) = (float)(local_38 - DOUBLE_803e8e30);
  }
  dVar4 = DOUBLE_803e8e38;
  dVar6 = (double)FLOAT_803e8e1c;
  dVar5 = (double)FLOAT_803e8e20;
  local_38 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 0x22));
  *(float *)(param_3 + 0x2a0) =
       (float)(dVar6 * (double)(float)(dVar5 - (double)((float)(local_38 - DOUBLE_803e8e38) /
                                                       (float)((double)CONCAT44(0x43300000,
                                                                                (uint)*(ushort *)
                                                                                       (iVar2 + 
                                                  0x3fe)) - DOUBLE_803e8e38))));
  if (*(float *)(param_3 + 0x2a0) < FLOAT_803e8e24) {
    *(float *)(param_3 + 0x2a0) = FLOAT_803e8e24;
  }
  if ((*(char *)(param_3 + 0x27a) != '\0') || (*(char *)(param_3 + 0x346) != '\0')) {
    if (*(char *)(iVar3 + 0x2c) == '\0') {
      uVar1 = (**(code **)(*DAT_803dd738 + 0x18))((double)FLOAT_803e8e28,param_2,param_3);
      if ((uVar1 & 1) == 0) {
        if ((uVar1 & 4) == 0) {
          if ((uVar1 & 2) == 0) {
            if ((uVar1 & 8) != 0) {
              *param_2 = *param_2 + 0x3ffc;
              *(undefined *)(iVar3 + 0x2c) = 3;
            }
          }
          else {
            *param_2 = *param_2 + -0x3ffc;
            *(undefined *)(iVar3 + 0x2c) = 3;
          }
        }
        else {
          *param_2 = *param_2 + 0x7ff8;
          *(undefined *)(iVar3 + 0x2c) = 3;
        }
      }
    }
    else {
      *(char *)(iVar3 + 0x2c) = *(char *)(iVar3 + 0x2c) + -1;
    }
    FUN_8003042c((double)FLOAT_803e8e18,dVar4,dVar5,dVar6,in_f5,in_f6,in_f7,in_f8,param_2,0x14,0,
                 param_5,param_6,param_7,param_8,param_9);
  }
  if (*(char *)(iVar3 + 0x2c) == '\0') {
    *param_2 = *param_2 +
               (short)(int)((float)((double)CONCAT44(0x43300000,
                                                     *(ushort *)(iVar3 + 0x20) - 0x7fff ^ 0x80000000
                                                    ) - DOUBLE_803e8e30) * FLOAT_803dc074 *
                           FLOAT_803e8e2c);
  }
  (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_2,param_3,1);
  return 0;
}

