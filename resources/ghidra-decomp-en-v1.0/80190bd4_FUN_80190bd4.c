// Function: FUN_80190bd4
// Entry: 80190bd4
// Size: 2252 bytes

void FUN_80190bd4(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar1 = FUN_802860dc();
  iVar5 = *(int *)(iVar1 + 0x4c);
  iVar4 = *(int *)(iVar1 + 0xb8);
  iVar6 = 0;
  do {
    if ((int)(uint)*(byte *)(param_3 + 0x8b) <= iVar6) {
      FUN_8019042c(iVar1);
      FUN_80286128(0);
      return;
    }
    switch(*(undefined *)(param_3 + iVar6 + 0x81)) {
    case 1:
      if (*(int *)(iVar5 + 0x14) == 0x47064) {
        FUN_80043034();
      }
      FUN_800552e8((int)*(char *)(iVar5 + 0x1a),0);
      break;
    case 2:
      iVar3 = *(int *)(iVar5 + 0x14);
      if (iVar3 == 0x48018) {
        uVar2 = FUN_800481b0(0x22);
        FUN_8004350c(uVar2,1,0);
        FUN_800200e8(0x36a,0);
        (**(code **)(*DAT_803dcaac + 0x50))(0xd,0,1);
        (**(code **)(*DAT_803dcaac + 0x50))(0xd,1,1);
        (**(code **)(*DAT_803dcaac + 0x50))(0xd,5,1);
        (**(code **)(*DAT_803dcaac + 0x50))(0xd,10,1);
        (**(code **)(*DAT_803dcaac + 0x50))(0xd,0xb,1);
        FUN_800200e8(0xe05,0);
      }
      else if (iVar3 < 0x48018) {
        if (iVar3 == 0x45dd6) {
          FUN_8004350c(0,0,1);
          uVar2 = FUN_800481b0(4);
          FUN_80043560(uVar2,0);
        }
        else if (iVar3 < 0x45dd6) {
          if (iVar3 == 0x2ba7) {
            FUN_8004350c(0,0,1);
            uVar2 = FUN_800481b0(0x12);
            FUN_80043560(uVar2,0);
            uVar2 = FUN_800481b0(0x1f);
            FUN_80043560(uVar2,1);
            FUN_80042f78(0x1f);
          }
          else if (iVar3 < 0x2ba7) {
            if (iVar3 == 0xc5d) {
              uVar2 = FUN_800481b0(0x21);
              FUN_8004350c(uVar2,1,0);
            }
          }
          else if (iVar3 == 0x43f83) {
            FUN_80042f78(0x21);
            uVar2 = FUN_800481b0(0x21);
            FUN_80043560(uVar2,1);
          }
        }
        else if (iVar3 == 0x47064) {
          FUN_80042f78(0x1c);
          uVar2 = FUN_800481b0(0x1c);
          FUN_80043560(uVar2,1);
          uVar2 = FUN_800481b0(0x1b);
          FUN_80043560(uVar2,0);
        }
        else if (iVar3 < 0x47064) {
          if (iVar3 == 0x46a40) {
            FUN_8004350c(0,0,1);
            uVar2 = FUN_800481b0(0xe);
            FUN_80043560(uVar2,0);
            uVar2 = FUN_800481b0(0x20);
            FUN_80043560(uVar2,1);
            FUN_80042f78(0x20);
          }
        }
        else if (iVar3 == 0x4800c) {
          FUN_80042f78(0x22);
          uVar2 = FUN_800481b0(0xd);
          FUN_80043560(uVar2,0);
          uVar2 = FUN_800481b0(0x22);
          FUN_80043560(uVar2,1);
        }
      }
      else if (iVar3 == 0x49c33) {
        FUN_800200e8(0x884,1);
        (**(code **)(*DAT_803dcaac + 0x50))(7,0,1);
        (**(code **)(*DAT_803dcaac + 0x50))(7,2,1);
        (**(code **)(*DAT_803dcaac + 0x50))(7,3,1);
        (**(code **)(*DAT_803dcaac + 0x50))(7,7,1);
        (**(code **)(*DAT_803dcaac + 0x50))(7,10,1);
        (**(code **)(*DAT_803dcaac + 0x50))(10,7,0);
LAB_80190e08:
        FUN_80042f78(7);
        FUN_8004350c(0,0,1);
        uVar2 = FUN_800481b0(7);
        FUN_80043560(uVar2,1);
      }
      else if (iVar3 < 0x49c33) {
        if (iVar3 == 0x4977d) goto LAB_80190e08;
        if (iVar3 < 0x4977d) {
          if (iVar3 == 0x48506) goto LAB_80190e08;
        }
        else if (iVar3 == 0x497f4) {
          FUN_8004350c(0,0,1);
          uVar2 = FUN_800481b0(10);
          FUN_80043560(uVar2,0);
          uVar2 = FUN_800481b0(0x27);
          FUN_80043560(uVar2,1);
          FUN_80042f78(0x27);
        }
      }
      else if (iVar3 == 0x4b666) {
        FUN_8004350c(0,0,1);
        uVar2 = FUN_800481b0(0x32);
        FUN_80043560(uVar2,0);
        uVar2 = FUN_800481b0(0x15);
        FUN_80043560(uVar2,1);
        FUN_80042f78(0x15);
      }
      else if (iVar3 < 0x4b666) {
        if (iVar3 == 0x4a533) {
          FUN_80042f78(0x28);
          uVar2 = FUN_800481b0(0x28);
          FUN_80043560(uVar2,1);
        }
      }
      else if (iVar3 == 0x4cde6) {
        FUN_8004350c(0,0,1);
        uVar2 = FUN_800481b0(10);
        FUN_80043560(uVar2,0);
      }
      break;
    case 3:
      if (*(int *)(iVar5 + 0x14) == 0x47064) {
        FUN_8004350c(0,0,1);
      }
      break;
    case 5:
      if (*(int *)(iVar5 + 0x14) == 0x47064) {
        FUN_80043074();
      }
      break;
    case 6:
      if (*(int *)(iVar5 + 0x14) == 0x47064) {
        FUN_80043034();
      }
      break;
    case 7:
      *(byte *)(iVar4 + 0xe) = *(byte *)(iVar4 + 0xe) | 4;
      FUN_8000bb18(iVar1,0x420);
      break;
    case 8:
      iVar3 = *(int *)(iVar5 + 0x14);
      if (iVar3 == 0x4977d) {
LAB_8019123c:
        FUN_80008b74(iVar1,iVar1,0x224,0);
        FUN_80008b74(iVar1,iVar1,0x223,0);
        FUN_80008b74(iVar1,iVar1,0x22e,0);
        FUN_80008b74(iVar1,iVar1,0x218,0);
        FUN_8005cef0(0);
        FUN_80088c94(1,1);
        FUN_80088e54((double)FLOAT_803e3e98,0);
      }
      else if (iVar3 < 0x4977d) {
        if (iVar3 == 0x4827e) {
LAB_801913e4:
          FUN_80008b74(iVar1,iVar1,0x247,0);
          FUN_80008b74(iVar1,iVar1,0x248,0);
          FUN_80055000();
          FUN_800200e8(0xef6,1);
        }
        else if (iVar3 < 0x4827e) {
          if (iVar3 == 0x4670d) goto LAB_801913e4;
          if ((iVar3 < 0x4670d) && (iVar3 == 0x43f83)) goto LAB_8019123c;
        }
        else {
          if (iVar3 == 0x49267) goto LAB_801913e4;
          if ((iVar3 < 0x49267) && (iVar3 == 0x48506)) goto LAB_801912b0;
        }
      }
      else if (iVar3 == 0x4b667) {
        FUN_80008b74(iVar1,iVar1,0x23a,0);
        FUN_80008b74(iVar1,iVar1,0x23b,0);
        (**(code **)(*DAT_803dcaac + 0x50))(0x15,2,1);
        FUN_80008b74(0,0,0x23e,0);
        FUN_80088e54((double)FLOAT_803e3e98,1);
      }
      else if (iVar3 < 0x4b667) {
        if (iVar3 == 0x4a533) {
LAB_801912b0:
          FUN_80008b74(iVar1,iVar1,0x217,0);
          FUN_80008b74(iVar1,iVar1,0x216,0);
          FUN_80008b74(iVar1,iVar1,0x22e,0);
          FUN_80008b74(iVar1,iVar1,0x218,0);
          FUN_8005cef0(1);
          FUN_80008b74(iVar1,iVar1,0x84,0);
          FUN_80008b74(iVar1,iVar1,0x8a,0);
          FUN_80088c94(1,0);
          FUN_80088e54((double)FLOAT_803e3e98,0);
        }
        else if ((0x4a532 < iVar3) && (0x4b665 < iVar3)) {
          FUN_80008b74(iVar1,iVar1,0x23a,0);
          FUN_80008b74(iVar1,iVar1,0x23b,0);
        }
      }
      else {
        if (iVar3 != 0x4cb84) {
          if ((0x4cb83 < iVar3) || (iVar3 != 0x4cb6a)) break;
          FUN_80008b74(iVar1,iVar1,0x238,0);
          FUN_80008b74(iVar1,iVar1,0x239,0);
          FUN_80088c94(1,1);
          FUN_80088e54((double)FLOAT_803e3e98,0);
        }
        FUN_800200e8(0xef6,0);
      }
    }
    iVar6 = iVar6 + 1;
  } while( true );
}

