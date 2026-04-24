// Function: FUN_80188cc0
// Entry: 80188cc0
// Size: 1552 bytes

undefined4 FUN_80188cc0(int param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar6 = 0;
  do {
    if ((int)(uint)*(byte *)(param_3 + 0x8b) <= iVar6) {
      return 0;
    }
    switch(*(undefined *)(param_3 + iVar6 + 0x81)) {
    case 2:
    case 0x65:
      iVar3 = *(int *)(iVar5 + 0x14);
      if (iVar3 == 0x49f5a) {
        FUN_80042f78(0x26);
        FUN_8004350c(0,0,1);
        uVar1 = FUN_800481b0(0x26);
        FUN_80043560(uVar1,0);
        uVar1 = FUN_800481b0(0xb);
        FUN_80043560(uVar1,1);
      }
      else if (iVar3 < 0x49f5a) {
        if (iVar3 == 0x451b9) {
          cVar2 = (**(code **)(*DAT_803dcaac + 0x40))(0xd);
          if (cVar2 == '\x02') {
            FUN_80042f78(0xb);
            FUN_8004350c(0,0,1);
            uVar1 = FUN_800481b0(0xb);
            FUN_80043560(uVar1,0);
          }
          else {
            FUN_80042f78(0x29);
            FUN_8004350c(0,0,1);
            uVar1 = FUN_800481b0(0x29);
            FUN_80043560(uVar1,0);
          }
        }
        else {
          if ((0x451b8 < iVar3) || (iVar3 != 0x43775)) goto LAB_80188e84;
          FUN_80042f78(0x29);
          FUN_8004350c(0,0,1);
          uVar1 = FUN_800481b0(0x29);
          FUN_80043560(uVar1,0);
        }
      }
      else if (iVar3 == 0x4cd65) {
        FUN_80042f78(0x41);
        FUN_8004350c(0,0,1);
        uVar1 = FUN_800481b0(0x41);
        FUN_80043560(uVar1,0);
        uVar1 = FUN_800481b0(0xb);
        FUN_80043560(uVar1,1);
      }
      else {
LAB_80188e84:
        FUN_80042f78(0x29);
        FUN_8004350c(0,0,1);
        uVar1 = FUN_800481b0(0x29);
        FUN_80043560(uVar1,0);
      }
      break;
    case 3:
    case 100:
      iVar3 = *(int *)(iVar5 + 0x14);
      if (iVar3 == 0x49f5a) {
        (**(code **)(*DAT_803dcaac + 0x50))(0xb,4,0);
      }
      else if (iVar3 < 0x49f5a) {
        if (iVar3 == 0x451b9) {
          cVar2 = (**(code **)(*DAT_803dcaac + 0x40))(0xd);
          if (cVar2 == '\x02') {
            FUN_8004350c(0,0,1);
            uVar1 = FUN_800481b0(0xd);
            FUN_800437bc(uVar1,0x3f3f);
            (**(code **)(*DAT_803dcaac + 0x50))(0xd,10,0);
            (**(code **)(*DAT_803dcaac + 0x50))(0xd,0xb,0);
            (**(code **)(*DAT_803dcaac + 0x50))(0xd,0xe,0);
          }
        }
        else if ((iVar3 < 0x451b9) && (iVar3 == 0x43775)) {
          FUN_8004350c(0,0,1);
          uVar1 = FUN_800481b0(7);
          FUN_800437bc(uVar1,0x3f3c);
        }
      }
      else if (iVar3 == 0x4cd65) {
        FUN_8004350c(0,0,1);
        uVar1 = FUN_800481b0(0xb);
        FUN_800437bc(uVar1,0x3f00);
      }
      break;
    case 5:
      iVar3 = *(int *)(iVar5 + 0x14);
      if (iVar3 == 0x451b9) {
        cVar2 = (**(code **)(*DAT_803dcaac + 0x40))(0xd);
        if (cVar2 == '\x02') {
          FUN_80043074();
        }
      }
      else if (iVar3 < 0x451b9) {
        if (iVar3 == 0x43775) {
LAB_8018904c:
          FUN_80043074();
        }
      }
      else if (iVar3 == 0x49f5a) goto LAB_8018904c;
      break;
    case 6:
      iVar3 = *(int *)(iVar5 + 0x14);
      if (iVar3 == 0x451b9) {
        cVar2 = (**(code **)(*DAT_803dcaac + 0x40))(0xd);
        if (cVar2 == '\x02') {
          FUN_80043034();
        }
      }
      else if (iVar3 < 0x451b9) {
        if (iVar3 == 0x43775) {
LAB_801890bc:
          FUN_80043034();
        }
      }
      else if (iVar3 == 0x49f5a) goto LAB_801890bc;
      break;
    case 7:
    case 0x66:
      iVar3 = *(int *)(iVar5 + 0x14);
      if (iVar3 == 0x49f5a) {
        FUN_800552e8(0x32,0);
      }
      else if (iVar3 < 0x49f5a) {
        if ((iVar3 == 0x451b9) &&
           (cVar2 = (**(code **)(*DAT_803dcaac + 0x40))(0xd), cVar2 == '\x02')) {
          (**(code **)(*DAT_803dcaac + 0x44))(0xb,5);
          FUN_800552e8(0x4e,0);
        }
      }
      else if (iVar3 == 0x4cd65) {
        FUN_800552e8(0x7f,0);
        (**(code **)(*DAT_803dcaac + 0x44))(0x41,2);
      }
      break;
    case 10:
      *(undefined *)(iVar4 + 0x1a) = 1;
      break;
    case 0xb:
      *(undefined *)(iVar4 + 0x1a) = 0;
      break;
    case 0xc:
      *(float *)(iVar4 + 4) = FLOAT_803e3b98;
      break;
    case 0xd:
      *(float *)(iVar4 + 4) = FLOAT_803e3ba8;
      break;
    case 0xe:
      *(float *)(iVar4 + 4) = FLOAT_803e3bac;
      break;
    case 0xf:
      *(float *)(iVar4 + 4) = FLOAT_803e3bb0;
      break;
    case 0x10:
      *(float *)(iVar4 + 8) = FLOAT_803e3b98;
      break;
    case 0x11:
      *(float *)(iVar4 + 8) = FLOAT_803e3ba8;
      break;
    case 0x12:
      *(float *)(iVar4 + 8) = FLOAT_803e3bac;
      break;
    case 0x13:
      *(float *)(iVar4 + 8) = FLOAT_803e3bb0;
      break;
    case 0x14:
      *(float *)(iVar4 + 0xc) = FLOAT_803e3b98;
      break;
    case 0x15:
      *(float *)(iVar4 + 0xc) = FLOAT_803e3ba8;
      break;
    case 0x16:
      *(float *)(iVar4 + 0xc) = FLOAT_803e3bac;
      break;
    case 0x17:
      *(float *)(iVar4 + 0xc) = FLOAT_803e3bb0;
      break;
    case 0x18:
      iVar3 = *(int *)(iVar4 + 0x10);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) & 0xbfff;
      }
      break;
    case 0x19:
      iVar3 = *(int *)(iVar4 + 0x10);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
      }
    }
    iVar6 = iVar6 + 1;
  } while( true );
}

