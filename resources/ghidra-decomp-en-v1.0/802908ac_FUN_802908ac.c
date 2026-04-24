// Function: FUN_802908ac
// Entry: 802908ac
// Size: 824 bytes

/* WARNING: Could not reconcile some variable overlaps */

char * FUN_802908ac(ulonglong param_1,int param_2,int param_3)

{
  char cVar1;
  char *pcVar2;
  int iVar3;
  byte bVar4;
  char *pcVar5;
  uint uVar6;
  uint uVar7;
  undefined8 local_78;
  undefined local_70 [2];
  undefined2 local_6e;
  ulonglong local_68;
  undefined4 local_60;
  uint local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined auStack64 [5];
  char local_3b;
  
  if (*(int *)(param_3 + 0xc) < 0x1fe) {
    local_70[0] = 0;
    local_6e = 0x20;
    local_78 = param_1;
    local_68 = param_1;
    FUN_8028dbe4(local_70,auStack64);
    if (local_3b == 'I') {
      if (((int)local_68._0_2_ & 0x8000U) == 0) {
        pcVar2 = (char *)(param_2 + -4);
        if (*(char *)(param_3 + 5) == 'A') {
          FUN_802917ec(pcVar2,&DAT_802c2b03);
        }
        else {
          FUN_802917ec(pcVar2,&DAT_802c2b07);
        }
      }
      else {
        pcVar2 = (char *)(param_2 + -5);
        if (*(char *)(param_3 + 5) == 'A') {
          FUN_802917ec(pcVar2,&DAT_802c2af9);
        }
        else {
          FUN_802917ec(pcVar2,&DAT_802c2afe);
        }
      }
    }
    else if (local_3b == 'N') {
      if ((local_78 & 0x8000000000000000) == 0) {
        pcVar2 = (char *)(param_2 + -4);
        if (*(char *)(param_3 + 5) == 'A') {
          FUN_802917ec(pcVar2,&DAT_802c2b15);
        }
        else {
          FUN_802917ec(pcVar2,&DAT_802c2b19);
        }
      }
      else {
        pcVar2 = (char *)(param_2 + -5);
        if (*(char *)(param_3 + 5) == 'A') {
          FUN_802917ec(pcVar2,&DAT_802c2b0b);
        }
        else {
          FUN_802917ec(pcVar2,&DAT_802c2b10);
        }
      }
    }
    else {
      local_50 = 0x1010000;
      local_4c = (uint)CONCAT12(100,local_4c._2_2_);
      local_48 = 0;
      local_44 = 1;
      local_60 = 0x1010000;
      local_5c = local_4c;
      local_58 = 0;
      local_54 = 1;
      iVar3 = FUN_80290ec0((short)((ushort)((uint)(int)local_68._0_2_ >> 4) & 0x7ff) + -0x3ff,
                           param_2,&local_60);
      if (*(char *)(param_3 + 5) == 'a') {
        *(undefined *)(iVar3 + -1) = 0x70;
      }
      else {
        *(undefined *)(iVar3 + -1) = 0x50;
      }
      pcVar5 = (char *)(iVar3 + -1);
      uVar6 = *(uint *)(param_3 + 0xc);
      uVar7 = uVar6;
      if (0 < (int)uVar6) {
        do {
          bVar4 = (byte)local_70[(int)uVar6 / 2 + -7] >> 4;
          if ((uVar6 & 1 ^ -((int)uVar6 >> 0x1f)) != -((int)uVar6 >> 0x1f)) {
            bVar4 = local_70[(int)uVar6 / 2 + -7];
          }
          bVar4 = bVar4 & 0xf;
          if (bVar4 < 10) {
            cVar1 = bVar4 + 0x30;
          }
          else if (*(char *)(param_3 + 5) == 'a') {
            cVar1 = bVar4 + 0x57;
          }
          else {
            cVar1 = bVar4 + 0x37;
          }
          pcVar5 = pcVar5 + -1;
          *pcVar5 = cVar1;
          uVar6 = uVar6 - 1;
          uVar7 = uVar7 - 1;
        } while (uVar7 != 0);
      }
      if ((*(int *)(param_3 + 0xc) != 0) || (*(char *)(param_3 + 3) != '\0')) {
        pcVar5 = pcVar5 + -1;
        *pcVar5 = '.';
      }
      pcVar5[-1] = '1';
      if (*(char *)(param_3 + 5) == 'a') {
        pcVar5[-2] = 'x';
      }
      else {
        pcVar5[-2] = 'X';
      }
      pcVar2 = pcVar5 + -3;
      *pcVar2 = '0';
      if (((int)local_68._0_2_ & 0x8000U) == 0) {
        if (*(char *)(param_3 + 1) == '\x01') {
          pcVar2 = pcVar5 + -4;
          *pcVar2 = '+';
        }
        else if (*(char *)(param_3 + 1) == '\x02') {
          pcVar2 = pcVar5 + -4;
          *pcVar2 = ' ';
        }
      }
      else {
        pcVar2 = pcVar5 + -4;
        *pcVar2 = '-';
      }
    }
  }
  else {
    pcVar2 = (char *)0x0;
  }
  return pcVar2;
}

