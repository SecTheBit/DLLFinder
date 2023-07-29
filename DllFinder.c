#include <windows.h>
#include <stdio.h>
#include <getopt.h>
#include <Tlhelp32.h>
#include <psapi.h>

static char *output_format;
static char *process_name;
static int priority_all=0;
static int priority_process_name=0;
static int priority_current_process=0; 

void ErrorMessagess(DWORD status){
    char buffer[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,NULL,status,MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),buffer,sizeof(buffer)/sizeof(char),NULL);
    printf("[+] Error is %s \n", buffer);
}

BOOL readAccess(PHANDLE threadContext, PSECURITY_DESCRIPTOR pSecurityDescriptor){
  DWORD desiredAccess=30;
  PGENERIC_MAPPING pgenericMapping;
  PRIVILEGE_SET privilegeSet;
  DWORD GrantedAccess;
  BOOL AccessStatus;
  DWORD grantedAccess=(DWORD)sizeof(privilegeSet);
  if(!(AccessCheck(pSecurityDescriptor,threadContext,desiredAccess,pgenericMapping,(PPRIVILEGE_SET)&privilegeSet,(LPDWORD)sizeof(privilegeSet),(PDWORD)&GrantedAccess,(PBOOL)&AccessStatus))!=0){
    return AccessStatus;
  }
}


void Dllparser(HANDLE prcsID){
  DWORD cb=1000;
  HMODULE lphmoduleArray[cb];
  HMODULE *lphmodule=lphmoduleArray;
  DWORD lpcbNeeded;
  unsigned char buffer[500];
  unsigned char buffer_psecuritydescriptor[500];
  PSECURITY_DESCRIPTOR  pSecurityDescriptor=buffer_psecuritydescriptor;
  HMODULE module_name;
  LPSTR lpbasename=buffer;
  DWORD lpnLengthNeeded;
  if((EnumProcessModulesEx(prcsID,lphmodule,cb,(LPDWORD)&lpcbNeeded,LIST_MODULES_ALL))!=0){
     cb=lpcbNeeded/sizeof(HMODULE);
  }
  if((EnumProcessModulesEx(prcsID,lphmodule,cb,(LPDWORD)&lpcbNeeded,LIST_MODULES_ALL))!=0){
    printf("[+] Enumerating Modules...\n");
  }
  
  for(int handlesw=1;handlesw<cb;handlesw++){

    module_name=lphmoduleArray[handlesw];

    if(GetModuleFileNameExA(prcsID,module_name,lpbasename,500)!=0){
      if((strstr(lpbasename,process_name)) == NULL){      
        
        if((GetFileSecurityA(lpbasename,OWNER_SECURITY_INFORMATION,pSecurityDescriptor,500,(DWORD *)&lpnLengthNeeded))!=0){
          
          HANDLE threadhandle=GetCurrentThread();
          PHANDLE tokenHandle;
          if(!(OpenThreadToken(threadhandle,TOKEN_QUERY,TRUE,tokenHandle))){       
            
        // checking read access
            BOOL read_access=readAccess(tokenHandle,pSecurityDescriptor); 
            if(read_access){
              printf("Module %s have Read Permission\n",lpbasename);
        }
      }
      }
     
    }
    }
  }
  
}

DWORD FindTargetProc( const char *targetprocess){
    HANDLE prcs;
    int flag;
    PROCESSENTRY32 pe32;
    DWORD pid=0;
    prcs=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(prcs==INVALID_HANDLE_VALUE){
        printf("[+] Error Occured while Taking Snapshot of the process");
        DWORD dwStatusError=GetLastError();
        ErrorMessagess(dwStatusError);
        exit(0);
    }
    else{
          pe32.dwSize=sizeof(PROCESSENTRY32);
          //retrieving info about the first process
          BOOL values=Process32First(prcs,(LPPROCESSENTRY32)&pe32);
          if(values==FALSE){
             printf("Error Occured while Copying the First Process to buffer");
            DWORD dwStatusError=GetLastError();
            ErrorMessagess(dwStatusError);
            exit(0);
          }
          
          else{
             while(Process32Next(prcs,(LPPROCESSENTRY32)&pe32)){
                int cmp=strcasecmp(targetprocess,pe32.szExeFile);
                if(cmp==0){
                    printf("\n[+] Process found\n");
                    pid=pe32.th32ProcessID;
                    flag=1;
                    break;
                }
                
             }
             if(flag !=1){
                printf("[+] Could not find the process\n");
                exit(0);
             }
          }

    }
    return pid;
}

/* void parse_output_format(){
  printf("[+] Output format is %s",output_format);

}
*/
void process_parsing(){
  DWORD PID=FindTargetProc(process_name);
    HANDLE prcsID;
    prcsID=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,PID);
    if(prcsID==NULL){
        printf("[+] Error: Can not create handle to process");
        DWORD dwStatusError=GetLastError();
        ErrorMessagess(dwStatusError);
        exit(0);
    }
    else{
      printf("[+] Handle to Process Obtained\n");
    }
    //using handle to find different modules 
    Dllparser(prcsID);

}
void set_priority(){
  if(priority_all){
    printf("[+] Dumping All Process DLL\n");
  }
  else{
    if(priority_process_name){
        printf("[+] Dumping Dll for Process: %s\n",process_name);
    }
    else {
        printf("[+] Dumping Dll for Current Process\n");
    }
  }
  process_parsing();

}

int main (int argc, char **argv)
{

  int c;

  while (1)
    {
      static struct option long_options[] =
        {
          {"process_name",  required_argument, 0, 'p'},
          {"all",  no_argument, 0, 'a'},
          {"current_process",  no_argument, 0, 'd'},
          {"output",    required_argument, 0, 'o'},
          {0, 0, 0, 0}
        };
      int option_index = 0;

      c = getopt_long (argc, argv, "adp:o:f:",
                       long_options, &option_index);

      if (c == -1) {
        set_priority(); 
        break;
      }
      switch (c)
        {
        case 0:
          if (long_options[option_index].flag != 0)
            break;
          printf ("option %s", long_options[option_index].name);
          if (optarg)
            printf (" with arg %s", optarg);
          printf ("\n");
          break;

        case 'a':
          priority_all=1;
          break;

        case 'p':
          priority_process_name=1;
          process_name=optarg;
          break;

        case 'o':
          output_format=optarg;
          break;
        case 'd':
          priority_current_process=1;
          break;

        case '?':
          /* getopt_long already printed an error message. */
          break;

        default:
          printf("default option");
        }
    }

  /* Print any remaining command line arguments (not options). */
  if (optind < argc)
    {
      printf ("non-option ARGV-elements: ");
      while (optind < argc)
        printf ("%s ", argv[optind++]);
      putchar ('\n');
    }

  exit (0);
}

