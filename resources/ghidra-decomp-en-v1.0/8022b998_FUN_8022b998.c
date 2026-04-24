// Function: FUN_8022b998
// Entry: 8022b998
// Size: 424 bytes

void FUN_8022b998(undefined4 param_1,undefined4 param_2,int param_3,int param_4,uint param_5)

{
  uint uVar1;
  short *psVar2;
  char cVar4;
  int iVar3;
  int iVar5;
  undefined8 uVar6;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20 [8];
  
  uVar6 = FUN_802860dc();
  psVar2 = (short *)((ulonglong)uVar6 >> 0x20);
  iVar5 = (int)uVar6;
  cVar4 = FUN_8002e04c();
  if (cVar4 != '\0') {
    if (param_3 == 0) {
      FUN_8003842c(psVar2,3,&local_28,&local_24,local_20,0);
      uVar1 = countLeadingZeros(2 - param_4);
      FUN_8022f1d8(*(undefined4 *)(iVar5 + 8),1,uVar1 >> 5 & 0xff);
    }
    else {
      FUN_8003842c(psVar2,4,&local_28,&local_24,local_20,0);
      uVar1 = countLeadingZeros(2 - param_4);
      FUN_8022f1d8(*(undefined4 *)(iVar5 + 0xc),1,uVar1 >> 5 & 0xff);
    }
    iVar3 = FUN_8002bdf4(0x20,0x604);
    *(undefined4 *)(iVar3 + 8) = local_28;
    *(undefined4 *)(iVar3 + 0xc) = local_24;
    *(undefined4 *)(iVar3 + 0x10) = local_20[0];
    *(char *)(iVar3 + 0x1a) = (char)((uint)(int)*psVar2 >> 8);
    *(char *)(iVar3 + 0x19) = (char)((uint)(int)psVar2[1] >> 8);
    *(undefined *)(iVar3 + 0x18) = 0;
    *(undefined *)(iVar3 + 4) = 1;
    *(undefined *)(iVar3 + 5) = 1;
    iVar3 = FUN_8002b5a0(psVar2);
    if (iVar3 != 0) {
      if (param_4 == 0) {
        FUN_8000bb18(iVar3,0x2a1);
      }
      else if (param_4 == 1) {
        FUN_8000bb18(iVar3,0x2a2);
      }
      else {
        FUN_8000bb18(iVar3,0x2b4);
        FUN_8002b884(iVar3,1);
      }
      if ((param_5 & 0xff) != 0) {
        FUN_8022e418(iVar3,1);
      }
      FUN_8022e600(iVar3,*(undefined2 *)(iVar5 + 0x40e));
      FUN_8022e54c((double)*(float *)(iVar5 + 0x410),iVar3);
    }
  }
  FUN_80286128();
  return;
}

