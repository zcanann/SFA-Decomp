// Function: FUN_8029100c
// Entry: 8029100c
// Size: 824 bytes

int * FUN_8029100c(double param_1,int param_2,int param_3)

{
  char cVar1;
  int *piVar2;
  char *pcVar3;
  byte bVar4;
  uint uVar5;
  uint uVar6;
  undefined8 local_78;
  undefined local_70 [2];
  undefined2 local_6e;
  double local_68;
  char local_60 [4];
  uint local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  char acStack_40 [5];
  char local_3b;
  
  if (*(int *)(param_3 + 0xc) < 0x1fe) {
    local_70[0] = 0;
    local_6e = 0x20;
    local_78 = param_1;
    local_68 = param_1;
    FUN_8028e344(param_1,(int)local_70,acStack_40);
    if (local_3b == 'I') {
      if (((int)local_68._0_2_ & 0x8000U) == 0) {
        piVar2 = (int *)(param_2 + -4);
        if (*(char *)(param_3 + 5) == 'A') {
          FUN_80291f4c(piVar2,(int *)&DAT_802c3283);
        }
        else {
          FUN_80291f4c(piVar2,(int *)&DAT_802c3287);
        }
      }
      else {
        piVar2 = (int *)(param_2 + -5);
        if (*(char *)(param_3 + 5) == 'A') {
          FUN_80291f4c(piVar2,(int *)&DAT_802c3279);
        }
        else {
          FUN_80291f4c(piVar2,(int *)&DAT_802c327e);
        }
      }
    }
    else if (local_3b == 'N') {
      if (((ulonglong)local_78 & 0x8000000000000000) == 0) {
        piVar2 = (int *)(param_2 + -4);
        if (*(char *)(param_3 + 5) == 'A') {
          FUN_80291f4c(piVar2,(int *)&DAT_802c3295);
        }
        else {
          FUN_80291f4c(piVar2,(int *)&DAT_802c3299);
        }
      }
      else {
        piVar2 = (int *)(param_2 + -5);
        if (*(char *)(param_3 + 5) == 'A') {
          FUN_80291f4c(piVar2,(int *)&DAT_802c328b);
        }
        else {
          FUN_80291f4c(piVar2,(int *)&DAT_802c3290);
        }
      }
    }
    else {
      local_50 = 0x1010000;
      local_4c = (uint)CONCAT12(100,local_4c._2_2_);
      local_48 = 0;
      local_44 = 1;
      local_60[0] = '\x01';
      local_60[1] = '\x01';
      local_60[2] = '\0';
      local_60[3] = '\0';
      local_5c = local_4c;
      local_58 = 0;
      local_54 = 1;
      pcVar3 = FUN_80291620((int)(short)((ushort)((uint)(int)local_68._0_2_ >> 4) & 0x7ff) - 0x3ff,
                            param_2,local_60);
      if (*(char *)(param_3 + 5) == 'a') {
        pcVar3[-1] = 'p';
      }
      else {
        pcVar3[-1] = 'P';
      }
      pcVar3 = pcVar3 + -1;
      uVar5 = *(uint *)(param_3 + 0xc);
      uVar6 = uVar5;
      if (0 < (int)uVar5) {
        do {
          bVar4 = (byte)local_70[(int)uVar5 / 2 + -7] >> 4;
          if ((uVar5 & 1 ^ -((int)uVar5 >> 0x1f)) != -((int)uVar5 >> 0x1f)) {
            bVar4 = local_70[(int)uVar5 / 2 + -7];
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
          pcVar3 = pcVar3 + -1;
          *pcVar3 = cVar1;
          uVar5 = uVar5 - 1;
          uVar6 = uVar6 - 1;
        } while (uVar6 != 0);
      }
      if ((*(int *)(param_3 + 0xc) != 0) || (*(char *)(param_3 + 3) != '\0')) {
        pcVar3 = pcVar3 + -1;
        *pcVar3 = '.';
      }
      pcVar3[-1] = '1';
      if (*(char *)(param_3 + 5) == 'a') {
        pcVar3[-2] = 'x';
      }
      else {
        pcVar3[-2] = 'X';
      }
      piVar2 = (int *)(pcVar3 + -3);
      *(char *)piVar2 = '0';
      if (((int)local_68._0_2_ & 0x8000U) == 0) {
        if (*(char *)(param_3 + 1) == '\x01') {
          piVar2 = (int *)(pcVar3 + -4);
          *(char *)piVar2 = '+';
        }
        else if (*(char *)(param_3 + 1) == '\x02') {
          piVar2 = (int *)(pcVar3 + -4);
          *(char *)piVar2 = ' ';
        }
      }
      else {
        piVar2 = (int *)(pcVar3 + -4);
        *(char *)piVar2 = '-';
      }
    }
  }
  else {
    piVar2 = (int *)0x0;
  }
  return piVar2;
}

