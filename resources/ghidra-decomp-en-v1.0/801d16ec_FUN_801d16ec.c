// Function: FUN_801d16ec
// Entry: 801d16ec
// Size: 652 bytes

/* WARNING: Removing unreachable block (ram,0x801d1958) */

void FUN_801d16ec(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  double dVar8;
  double dVar9;
  undefined8 in_f31;
  int local_38;
  int local_34;
  undefined4 local_30;
  uint uStack44;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar1 = FUN_802860dc();
  iVar6 = *(int *)(iVar1 + 0xb8);
  iVar5 = *(int *)(iVar1 + 0x4c);
  iVar2 = FUN_8002b9ec();
  iVar3 = FUN_8002b9ac();
  iVar4 = FUN_8002b044(iVar1);
  if (iVar4 == 0) {
    if (*(char *)(iVar6 + 0x136) == '\b') {
      while (iVar2 = FUN_800374ec(iVar1,&local_38,0,0), iVar2 != 0) {
        if (local_38 == 0x7000b) {
          *(ushort *)(iVar1 + 6) = *(ushort *)(iVar1 + 6) | 0x4000;
          FUN_80035f00(iVar1);
          FUN_8001ff3c((int)*(short *)(iVar6 + 0x134));
          FUN_800200e8(0x12e,0);
          if (*(short *)(iVar1 + 0x46) == 0x658) {
            FUN_800999b4((double)FLOAT_803e52a8,iVar1,0xff,0x28);
          }
          else {
            FUN_800999b4((double)FLOAT_803e52a8,iVar1,6,0x28);
          }
          FUN_8000bb18(iVar1,0x58);
        }
      }
    }
    else {
      if (*(char *)(iVar6 + 0x139) != '\0') {
        *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(iVar5 + 8);
        *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(iVar5 + 0xc);
        *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(iVar5 + 0x10);
        *(undefined *)(iVar1 + 0x36) = 0xff;
        *(undefined *)(iVar6 + 0x139) = 0;
      }
      *(undefined4 *)(iVar6 + 0x10c) = *(undefined4 *)(iVar6 + 0x108);
      dVar8 = (double)FUN_800216d0(iVar2 + 0x18,iVar1 + 0x18);
      if (iVar3 == 0) {
        dVar8 = (double)FUN_802931a0();
        *(float *)(iVar6 + 0x108) = (float)dVar8;
      }
      else {
        dVar9 = (double)FUN_800216d0(iVar3 + 0x18,iVar1 + 0x18);
        if (dVar9 <= dVar8) {
          dVar8 = (double)FUN_802931a0();
          *(float *)(iVar6 + 0x108) = (float)dVar8;
        }
        else {
          dVar8 = (double)FUN_802931a0(dVar8);
          *(float *)(iVar6 + 0x108) = (float)dVar8;
        }
        uStack44 = (uint)*(byte *)(iVar5 + 0x1f);
        local_30 = 0x43300000;
        if (*(float *)(iVar6 + 0x108) <
            (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e52c0)) {
          (**(code **)(**(int **)(iVar3 + 0x68) + 0x28))(iVar3,iVar1,0,1);
        }
      }
      iVar2 = FUN_8003687c(iVar1,&local_34,0,0);
      if (iVar2 != 0) {
        if (iVar2 == 0x10) {
          FUN_8002b050(iVar1,300);
        }
        else {
          FUN_8002ac30(iVar1,0xf,200,0,0,1);
          if (*(short *)(local_34 + 0x46) != 0x416) {
            if ((*(byte *)(iVar6 + 0x137) & 0x10) == 0) {
              FUN_8000bb18(iVar1,0x9d);
            }
            *(byte *)(iVar6 + 0x137) = *(byte *)(iVar6 + 0x137) | 0x10;
          }
        }
      }
      FUN_801d083c(iVar1,iVar6,iVar5);
    }
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  FUN_80286128();
  return;
}

