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
    printf("=================================================================================\n");
    printf("=================================================================================\n");
  }
  
  for(int handlesw=1;handlesw<cb;handlesw++){

    module_name=lphmoduleArray[handlesw];

    if(GetModuleFileNameExA(prcsID,module_name,lpbasename,500)!=0){
      if((strstr(lpbasename,process_name)) == NULL){      
          printf("[+] Module Found %s\n",lpbasename);

     
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
                    printf("[+] Process found\n");
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
  if(priority_process_name){
        process_parsing();
    }
  else {
        printf("[+] Process Name Not provided\n");
        exit(0);
    }
  
}

int main (int argc, char **argv)
{

  int c;

  while (1)
    {
      static struct option long_options[] =
        {
          {"process_name",  required_argument, 0, 'p'},
          {0, 0, 0, 0}
        };
      int option_index = 0;

      c = getopt_long (argc, argv, "p:",
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

        case 'p':
          priority_process_name=1;
          process_name=optarg;
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

