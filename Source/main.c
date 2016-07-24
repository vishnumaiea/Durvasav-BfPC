

/* BETA TEST-222222222222222222222222222222222222222222222222222222  */
/* 1. removed all shorts - worked improvement                        */
/* 2. added static to all charset                                    */
/* 3. use of CMPLVL macro                                            */
/* 4. all arrays are now static                                      */
/* 5. checks if the CUSTOM.CST file exists                           */
/* 6. relocated the "PLease wait..."                                 */
/* 7. relocated the 'output[]='\0'                                   */
/* 8. comp var not removed                                           */
/* 9. CLOCK_PER_SEC is 1000                                          */
/* 10. limit on retries for 'Unexpected hash length" (new 'rpt' var) */
/* 11. '1' is used for confirming YES                                */
/* 12. removed warning about wordlist file size                      */
/* 13. corrected version problem in wordlist output file             */
/* 14. added intenation in the loops                                 */
/* 15. solved the "End of retries" bug using 'rpt=0' definition      */
/* 16. change in "Start Brute forcing ?"                             */
/* 17. return to main() when custom.cst deos not exist               */
/* 18. display 'so far cracked' hashes in compare2                   */
/* 19. retry on characterset selection                               */
/* 20. relocation on function startup(clock_t vars etc)              */
/* 21. change in 'stop' assignment for custom charset                */
/* 22. change in "Brute forcing completed"                           */
/* 23. replaced 'exit(0)' with main() for 'hashin[0]=0'              */
/* 24. replaced 'exit(0) with main() for 'method=0'                  */
/* 25. replaced 'exit(0) with main() for while loop of hashin retry  */
/* 26. replaced 'exit(0) with main() for filename[0]=='0'            */
/* 27. correctd "\n\n\tLast Hash    =  %s\n\t" by adding ' ' at end  */
/*     -(change removed)                                             */
/* 28. removed 'about() for 12' from main()                          */
/* 29. replaced 'exit(0)' with main() for 'if(set==0)' in main()     */
/* 30. replaced 'exit(0)' with main() for 'if(op_mod==0)'            */
/* 31. added b!='1' with if(b!='y'&&b!='Y')                          */
/* 32. replaced 'system("cls")' with 'clrscr(). use of new package   */
/* 33. replaced 'exit(0)' in "Sorry ! I'm unable.." to 'main()'      */
/* 34. use of MAXLEN and MINLEN macros                               */
/* 35. use of hash length macros                                     */
/* 36. use of character set length limit macro - CSTLIMIT            */
/* 37. found a bug in 'scanf()' routine. not cured                   */
/* 38. added hash name to the output file of cracked hashes          */
/* 39. addd secondary comparison in all compare functions            */
/* 40. added "That's too large to handle" msg in Compare_2s          */
/* 41. added 'FNAMELEN' macro                                        */
/* 42. removed '_' from the file output headers                      */
/* 43. return changed to 'main()' instead of exit in 'about()'       */
/* 44. relocated 'intial++' on main()                                */
/* 45. destroyed bug in '_Compare' funcs by 'a ='x'' intialization   */
/* 46. length checking on custom charset file. new 'custom_set'      */
/* 47. change in password length fetching messages                   */
/* 48. removed printing mistake in 11 and 12 lengths                 */


//Threading------------------------------------------------------------

/* 49. language standard changed to C99                              */
/* 50. use of function pointers in the function call system          */
/* 51. slight change in about output                                 */
/* 52. small change in the custom charset msg : changed 94 to 256    */
/* 53. added colour to the header                                    */
/* 54. added colour to about()                                       */
/* 55. replaced "256" with "CSTLIMIT" in custom charset selection    */
/* 56. support for space character in the custom charset file        */
/* 57. added LIGHTRED color for errors                               */


/*  OpenSSL Implementation                                           */


/**************************************************************

  Name: Durvasav BfPC
  Version: 3.2.1.21 (Threaded)
  Description: Bruteforce Password Cracker (BfPC)
  Author: Vishnu M Aiea (AYGENT543)
  IDE: Orwell DevC++ 5.8.3
  Platform: Microsoft(R) Windows(TM) 7, 32bit
  Date: 12/02/13 23:19
  Copyright: Copyright (c) 2013 Vishnu M Aiea
  Contact: vishnumaiea@gmail.com
  Website : www.vishnumaiea.in
  License: GNU GENERAL PUBLIC LICENSE version 3
  
**************************************************************/


//last change on 12-05-13 11:24


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>
#include <conio2.h>  /* borland extension */
#include <time.h>
#include "durvasav.h"

int hcat[8] = {MD4LEN,MD5LEN,SHA0LEN,SHA1LEN,SHA224LEN,SHA256LEN,SHA384LEN,SHA512LEN};

void Hash_Perform(int,int,int,int,int,int);
void Hash_Compare(int,int,int,int,int,int);
void Hash_Compare_2(int,int,int,int,int,int);
void Hash_Print(int,int,int,int,int,int);
void Hash_Fout(int,int,int,int,int,int);

void Pseudo_Perform(int,int,int,int,int,int);
void Pseudo_Compare(int,int,int,int,int,int);
void Pseudo_Print(int,int,int,int,int,int);
void Pseudo_Fout(int,int,int,int,int,int);

void MD4_Convert(char *,char *,int);
void MD5_Convert(char *,char *,int);
void SHA0_Convert(char *,char *,int);
void SHA1_Convert(char *,char *,int);
void SHA224_Convert(char *,char *,int);
void SHA256_Convert(char *,char *,int);
void SHA384_Convert(char *,char *,int);
void SHA512_Convert(char *,char *,int);

void header(void);
void about(void);
void landing(int,int,int);


int main()          /* main starts */
{
	FILE *fp;
	void (*hash_func)(); //function pointer
	unsigned int set,emin,emax;
	static unsigned int intial;  /* for welcome screen */
	int i,op_mod,htyp;   /* output mode & hashtype */
	char a,b,c;
	char custom_set[300]={'\0'};
	clrscr();   /* clears screen */
	
	
	if(intial==0)   /* welcome screen */
	{
		header();
		printf("\n\n\n\n\n\n\n\n\n\n\t\t\t   When Imagination Fails ! ");
		c=getch();
		
		intial++;
		
		if(c=='0' || c=='x' || c=='X' || c=='q' || c=='Q')
		{
			exit(0);
		}
		else if(c=='9'|| c=='a' || c=='A')
		{
			about();
		}
		
	}


do{   /* loop for repetition */
 clrscr();
 header();
 printf("\n\n\n\n\t1. [MD4]         2. [MD5]         3. [SHA0]         4. [SHA1]");
 printf("\n\n\t5.[SHA224]       6.[SHA256]       7.[SHA384]        8.[SHA512]");
 printf("\n\n\t9.[Pseudo]");
 printf("\n\n\n\tSelect hash type : ");
 scanf("%d",&htyp);
 
	if(htyp==0)      /* exit on zero */
	{
		exit(0);    
	}

	if(htyp<1||htyp>9)
	{
		textcolor(LIGHTRED);
		printf("\n\n\tInvalid choice ! Try again. ");
		textcolor(LIGHTGRAY);
		a=getch();
	}
	else
	{
		break;      /* true and continue */
	}

}while(a!='0');   /* do..while ends*/

if(a=='0')
{
	exit(0);     /* zero for exit */
}	


/* selecting characterset */
do{
 clrscr();
 header();
 printf("\n\n\n\n\t1.[0...9]        2.[a...z]        3.[A...Z]         4.[0...z]");
 printf("\n\n\t5.[0...Z]        6.[a...Z]        7.[0..a..Z]       8. [All]");
 printf("\n\n\t9.[Custom]");
 printf("\n\n\n\tSelect character set : ");
 scanf("%d",&set);

	if(set==0)
	{
  		main();
	}

	if((set<1)||(set>9))
	{
		textcolor(LIGHTRED);
 	 	printf("\n\n\tInvalid choice ! Try again. ");
 	 	textcolor(LIGHTGRAY);
 	 	a=getch();
	}
	else
	{
		break;
	}
}while(a!='0');

if(a=='0')
{
	main();
}

	if(set==9)
	{
		clrscr();
		header();
		fp = fopen("CUSTOM.CST","r");
		if(fp==NULL)
		{
			fp = fopen("CUSTOM.CST","w"); /* create file if it does not already exist */
	   	 	fclose(fp);
		}
		else
		{
			fclose(fp);
		}
	    printf("\n\n\n\n\tPlease  open  the  \"custom.cst\"  file from the root and add max.");
	    printf("\n\n\tof %d  characters  to the file  in one line  with a terminating",CSTLIMIT);
	    printf("\n\n\tnewline character.");
	    printf("\n\n\n\tContinue now ?  (Y / N) ");
	    b=getche();
	    if(b!='y'&&b!='Y'&&b!='1')
	    {
	    	main();
	    }
	    else
	    {	    	
	        fp = fopen("CUSTOM.CST","r");
			if(fp==NULL)
			{
				textcolor(LIGHTRED);
				printf("\n\n\n\tThe file does not exist. ");
				textcolor(LIGHTGRAY);
				getch();
				main();
			}
			else
			{
				fgets(custom_set,CSTLIMIT+1,fp);
				custom_set[(strlen(custom_set)-1)] = '\0';
				
				if(strlen(custom_set)==0)
				{
					printf("\n\n\tFile is empty and default is applied. ");
					getch();
				}
				else if(strlen(custom_set)>CSTLIMIT)
				{
					printf("\n\n\tCharacter set is too long. Max. is %d ",CSTLIMIT);
					getch();
					main();
				}
				fclose(fp);
				printf("\n");
			}
	    }
	}


printf("\n\n\tMin. length of password (2) : ");
scanf("%d",&emin);

	if(emin<=0)
	{
  		main();
	}

	if((emin<MINLEN)||(emin>MAXLEN))
	{
 	 	printf("\n\n\tI don't think you can read ! ");
 	 	getch();
 	 	main();
	}
printf("\n\n\tMax. length of password (12) : ");
scanf("%d",&emax);

	if(emax<=0)
	{
  		main();
	}

	if(emax<emin)
	{
		printf("\n\n\tThat's not gonna happen ;) ");
  		getch();
  		main();
	}

	if(emax>MAXLEN)
	{
  		printf("\n\n\tMay be you are blind ! ");
  		getch();
  		main();
	}
/* footprint completed */


clrscr();
header();
printf("\n\n\n\n\tHow you'd like to get the output ?");
printf("\n\n\n\t1.Perform      2.Compare      3.Print      4.Wordlist");
printf("\n\n\n\n\n\tEnter choice : ");
scanf("%d",&op_mod);

	if(op_mod==0)
	{
		main();
	}

	else if(op_mod==9)
	{
		about();
	}

	else if(op_mod<1||op_mod>4)
	{
		textcolor(LIGHTRED);
		printf("\n\n\tInvalid choice ! ");
		textcolor(LIGHTGRAY);
		getch();
		main();
	}


//function call system


if(htyp>=1 && htyp<=8)
{
	switch(op_mod)
		{
			case 1:
				hash_func = Hash_Perform;
				break;
			case 2:
				hash_func = Hash_Compare;
				break;
			case 3:
				hash_func = Hash_Print;
				break;
			case 4:
				hash_func = Hash_Fout;
				break;
				
			default:
			textcolor(LIGHTRED);
			printf("\n\n\tInvalid option selection !");
			textcolor(LIGHTGRAY);
			break;
		}
}

else if(htyp==9)
{
	switch(op_mod)
		{
			case 1:
				hash_func = Pseudo_Perform;
				break;
			case 2:
				hash_func = Pseudo_Compare;
				break;
			case 3:
				hash_func = Pseudo_Print;
				break;
			case 4:
				hash_func = Pseudo_Fout;
				break;
				
			default:
			textcolor(LIGHTRED);
			printf("\n\n\tInvalid option selection !");
			textcolor(LIGHTGRAY);
			break;
		}
}


switch(set)
		{
			case 1:
			hash_func(emin,emax,0,9,0,htyp);
			break;
			
			case 2:
			hash_func(emin,emax,10,35,0,htyp);
			break;
			
			case 3:
			hash_func(emin,emax,36,61,0,htyp);
			break;
			
			case 4:
			hash_func(emin,emax,0,35,0,htyp);
			break;
			
			case 5:
			hash_func(emin,emax,0,35,1,htyp);
			break;
			
			case 6:
			hash_func(emin,emax,10,61,0,htyp);		
			break;
			
			case 7:
			hash_func(emin,emax,0,61,0,htyp);			
			break;
			
			case 8:
			hash_func(emin,emax,0,93,0,htyp);
			break;
			
			case 9:
			hash_func(emin,emax,0,0,2,htyp);
			break;
			
			default:
			textcolor(LIGHTRED);
			printf("\n\n\tInvalid option selection !");
			textcolor(LIGHTGRAY);
			break;				
		}

}           /* main ends */
/*<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<*/



/*############################################################################*/
/*############################################################################*/



/*>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>*/
/*          HASH  P E R F O R M             */
void Hash_Perform(int emin,int emax,register int start,register int stop,int cpm,int htyp)
{
FILE *fp;
void (* hash_func)(); //function pointer
register unsigned int v, u, t, s, r, q, p, n, m, k, j, i;
char hashout[hcat[htyp-1]+1];
static char output[MAXLEN+1];
char a;
char hash_type[7]; //stores name of hash
clock_t starts,stops;
double timespent;
static char charset[CSTLIMIT+1]="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+-,.'`/:@;<>?=[]^_{}~|";  /* characterset */
charset[92]='\\';   /* backslash */
charset[93]='\"';   /* double quote */
charset[94]='\0';
clrscr();


switch(htyp)
{
	case 1:
		hash_func = MD4_Convert;
		strcpy(hash_type,"MD4");
		break;
	case 2:
		hash_func = MD5_Convert;
		strcpy(hash_type,"MD5");
		break;
	case 3:
		hash_func = SHA0_Convert;
		strcpy(hash_type,"SHA0");
		break;
	case 4:
		hash_func = SHA1_Convert;
		strcpy(hash_type,"SHA1");
		break;
	case 5:
		hash_func = SHA224_Convert;
		strcpy(hash_type,"SHA224");
		break;
	case 6:
		hash_func = SHA256_Convert;
		strcpy(hash_type,"SHA256");
		break;
	case 7:
		hash_func = SHA384_Convert;
		strcpy(hash_type,"SHA384");
		break;
	case 8:
		hash_func = SHA512_Convert;
		strcpy(hash_type,"SHA512");
		break;
}


if(cpm==1)
{
	strcpy(charset,"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"); /* this is necessary */
}


/*******************************************************/
/*               CUSTOM CHARSET                        */
if(cpm==2)
{
	fp = fopen("CUSTOM.CST","r");
	fgets(charset,CSTLIMIT+1,fp);
	charset[(strlen(charset)-1)] = '\0';
	fclose(fp);
	
	start = 0;
	stop = (strlen(charset))-1;
}
/*******************************************************/


header();
printf("\n\n\n\n\t%s : Perform",hash_type);

if(cpm==2)
{
	printf(" - Custom charset.");
}
else
{
	landing(start,stop,cpm);
}


printf("\n\n\tTotal no. of combinations = %d^%d",stop-start+1,emax);
printf("\n\n\n\tStart Bruteforcing ?  (Y / N) ");
a=getche();

if(a=='n'||a=='N')
{
	main();
}
else if(a=='y'||a=='Y'||a=='1')    /* main else if */
{
 printf("    Please wait... ");
 starts = clock();  /* stopwatch starts */

if((emin<=2)&&(emax>=2))    /* execution condition */
{
output[2]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
  output[1]=charset[j];
  hash_func(output,hashout,2);   /* output goes to the input of function */
 }
}    /* loop ends */
}    /* if ends */


if((emin<=3)&&(emax>=3))
{
output[3]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
   output[2]=charset[k];
   hash_func(output,hashout,3);
  }
 }
} /* loop ends */
} /* if ends */


if((emin<=4)&&(emax>=4))
{
output[4]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
    output[3]=charset[m];
    hash_func(output,hashout,4);
   }
  }
 }
}      /* loop ends */
}      /* if ends */


if((emin<=5)&&(emax>=5))
{
output[5]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
     output[4]=charset[n];
     hash_func(output,hashout,5);
    }
   }
  }
 }
}    /* loop ends */
}    /* if ends */


if((emin<=6)&&(emax>=6))
{
output[6]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
      output[5]=charset[p];
      hash_func(output,hashout,6);
     }
    }
   }
  }
 }
}    /* loop ends */
}    /* if ends */


if((emin<=7)&&(emax>=7))
{
output[7]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
       output[6]=charset[q];
       hash_func(output,hashout,7);
      }
     }
    }
   }
  }
 }
}   /* loop ends */
}   /* if ends */


if((emin<=8)&&(emax>=8))
{
output[8]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
        output[7]=charset[r];
        hash_func(output,hashout,8);
       }
      }
     }
    }
   }
  }
 }
}   /* loop ends */
}   /* if ends */


if((emin<=9)&&(emax>=9))
{
output[9]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	     output[8]=charset[s];
	     hash_func(output,hashout,9);
	    }
       }
      }
     }
    }
   }
  }
 }
}   /* loop ends */
}   /* if ends */


if((emin<=10)&&(emax>=10))
{
output[10]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	      output[9]=charset[t];
	      hash_func(output,hashout,10);
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
}     /* loop ends */
}     /* if ends */


if((emin<=11)&&(emax>=11))
{
output[11]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	     output[9]=charset[t];
	      for(u=start;u<=stop;u++)
	      {
	       output[10]=charset[u];
	       hash_func(output,hashout,11);
	      }
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
}  /* loop ends */
}  /* if ends */


if((emin<=12)&&(emax>=12))
{
output[12]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	     output[9]=charset[t];
	      for(u=start;u<=stop;u++)
	      {
	      output[10]=charset[u];
	       for(v=start;v<=stop;v++)
	       {
	        output[11]=charset[v];
	        hash_func(output,hashout,12);
	       }
	      }
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
}   /* loop ends */
}   /*  if ends */

stops = clock();
printf("\n\n\tBruteforcing completed !");
timespent = (double)(stops-starts)/CLOCKS_PER_SEC; /* calculating time taken */
printf("\n\n\n\tTime Taken   =  %f sec ",timespent);
printf("\n\n\tLast Output  =  %s",output);
printf("\n\n\tLast Hash    =  %s ",hashout);
}

getch();	     /* main else if ends */
main();
}            /* function ends */
/*<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<*/



/*>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>*/
/*          HASH  C O M P A R E            */
void Hash_Compare(int emin,int emax,register int start,register int stop,int cpm,int htyp)
{
FILE *fp;
void (* hash_func)();
register unsigned int v, u, t, s, r, q, p, n, m, k, j, i;
char hashout[hcat[htyp-1]+1];
char hashin[hcat[htyp-1]+100]; //to prevent overflow error and exit
static char output[MAXLEN+1];
register int comp;
int method,rpt=0;
char a;
char hash_type[7];
clock_t starts,stops;
double timespent;
static char charset[CSTLIMIT+1]="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+-,.'`/:@;<>?=[]^_{}~|";  /* characterset */
charset[92]='\\';   /* backslash */
charset[93]='\"';   /* double quote */
charset[94]='\0';
clrscr();


switch(htyp)
{
	case 1:
		hash_func = MD4_Convert;
		strcpy(hash_type,"MD4");
		break;
	case 2:
		hash_func = MD5_Convert;
		strcpy(hash_type,"MD5");
		break;
	case 3:
		hash_func = SHA0_Convert;
		strcpy(hash_type,"SHA0");
		break;
	case 4:
		hash_func = SHA1_Convert;
		strcpy(hash_type,"SHA1");
		break;
	case 5:
		hash_func = SHA224_Convert;
		strcpy(hash_type,"SHA224");
		break;
	case 6:
		hash_func = SHA256_Convert;
		strcpy(hash_type,"SHA256");
		break;
	case 7:
		hash_func = SHA384_Convert;
		strcpy(hash_type,"SHA384");
		break;
	case 8:
		hash_func = SHA512_Convert;
		strcpy(hash_type,"SHA512");
		break;
}


if(cpm==1)
{
	strcpy(charset,"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");  /* redefining char set */
}


/*******************************************************/
/*               CUSTOM CHARSET                        */
if(cpm==2)
{
	fp = fopen("CUSTOM.CST","r");
	fgets(charset,CSTLIMIT+1,fp);
	charset[(strlen(charset)-1)] = '\0';
	fclose(fp);
	
	start = 0;
	stop = (strlen(charset))-1;
}
/*******************************************************/

header();
printf("\n\n\n\n\tAvailable methods for importing hashes.");
printf("\n\n\n\t1.Input Hash\t\t2.Open File");
printf("\n\n\n\n\tSelect method : ");
scanf("%d",&method);

if(method==0)
{
	main();
}

if(method==2)
{
	Hash_Compare_2(emin,emax,start,stop,cpm,htyp);
}

if(method<1 || method>9)
{
	textcolor(LIGHTRED);
	printf("\n\n\n\tInvalid choice ! ");
	textcolor(LIGHTGRAY);
	getch();
	main();
}
else
{
	clrscr();
}


do{         /* loop for repetition */
header();
printf("\n\n\n\n\t%s : Compare",hash_type);

if(cpm==2)
{
	printf(" - Custom charset.");
}
else
{
	landing(start,stop,cpm);
}

if(rpt==4) /* end of retries */
{
	textcolor(LIGHTRED);
	printf("\n\n\n\tEnd of retries ! ");
	textcolor(LIGHTGRAY);
	getch();
	main();
}


printf("\n\n\tEnter %s Hash : ",hash_type);
scanf("%s",hashin);

if(hashin[0]=='0' && strlen(hashin)<2)   /* zero for exit */
{
	main();
}

if(strlen(hashin)>(hcat[htyp-1])||strlen(hashin)<(hcat[htyp-1]))
{
 printf("\n\n\tUnexpected hash length !");
 rpt++;    /* counting the retries  */
 a=getch();
 clrscr();
}
else
{
	break;
}
}while(a!='0');          /* zero for exit */


if(a==0)
{
	main();
}


printf("\n\tTotal no. of combinations = %d^%d",stop-start+1,emax);
printf("\n\n\n\tStart Bruteforcing ?  (Y / N) ");
a=getche();
if(a=='n'||a=='N')
{
	main();
}
else if(a=='y'||a=='Y'||a=='1')    /* main else if */
{
printf("    Please wait... ");

starts = clock();

if((emin<=2)&&(emax>=2))
{
output[2]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
  output[1]=charset[j];
  hash_func(output,hashout,2);
  comp = strncmp(hashin,hashout,CMPLVL);
  if(comp==0)
  {
  	comp = strcmp(hashin,hashout);
  	if(comp==0)
  	goto out;
  }
 }
}    /* loop ends */
}    /* if ends */


if((emin<=3)&&(emax>=3))
{
output[3]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
   output[2]=charset[k];
   hash_func(output,hashout,3);
   comp = strncmp(hashin,hashout,CMPLVL);
   if(comp==0)
   {
  	 comp = strcmp(hashin,hashout);
  	 if(comp==0)
  	 goto out;
   }
  }
 }
} /* loop ends */
} /* if ends */


if((emin<=4)&&(emax>=4))
{
output[4]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
    output[3]=charset[m];
    hash_func(output,hashout,4);
    comp = strncmp(hashin,hashout,CMPLVL);
    if(comp==0)
    {
  	  comp = strcmp(hashin,hashout);
  	  if(comp==0)
  	  goto out;
    }
   }
  }
 }
}      /* loop ends */
}      /* if ends */


if((emin<=5)&&(emax>=5))
{
output[5]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
     output[4]=charset[n];
     hash_func(output,hashout,5);
     comp = strncmp(hashin,hashout,CMPLVL);
     if(comp==0)
     {
  	   comp = strcmp(hashin,hashout);
  	   if(comp==0)
  	   goto out;
     }
    }
   }
  }
 }
}    /* loop ends */
}    /* if ends */


if((emin<=6)&&(emax>=6))
{
output[6]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
      output[5]=charset[p];
      hash_func(output,hashout,6);
      comp = strncmp(hashin,hashout,CMPLVL);
      if(comp==0)
      {
  	    comp = strcmp(hashin,hashout);
  	    if(comp==0)
  	    goto out;
      }
     }
    }
   }
  }
 }
}    /* loop ends */
}    /* if ends */


if((emin<=7)&&(emax>=7))
{
output[7]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
       output[6]=charset[q];
       hash_func(output,hashout,7);
       comp = strncmp(hashin,hashout,CMPLVL);
       if(comp==0)
       {
  	     comp = strcmp(hashin,hashout);
  	     if(comp==0)
  	     goto out;
       }
      }
     }
    }
   }
  }
 }
}  /* loop ends */
}  /* if ends */


if((emin<=8)&&(emax>=8))
{
output[8]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
        output[7]=charset[r];
        hash_func(output,hashout,8);
        comp = strncmp(hashin,hashout,CMPLVL);
        if(comp==0)
        {
  	      comp = strcmp(hashin,hashout);
  	      if(comp==0)
  	      goto out;
        }
       }
      }
     }
    }
   }
  }
 }
}   /* loop ends */
}   /* if ends */


if((emin<=9)&&(emax>=9))
{
output[9]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	     output[8]=charset[s];
	     hash_func(output,hashout,9);
         comp = strncmp(hashin,hashout,CMPLVL);
	     if(comp==0)
         {
  	       comp = strcmp(hashin,hashout);
  	       if(comp==0)
  	       goto out;
         }
	    }
       }
      }
     }
    }
   }
  }
 }
}   /* loop ends */
}   /* if ends */


if((emin<=10)&&(emax>=10))
{
output[10]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	      output[9]=charset[t];
	      hash_func(output,hashout,10);
          comp = strncmp(hashin,hashout,CMPLVL);
	      if(comp==0)
          {
  	        comp = strcmp(hashin,hashout);
  	        if(comp==0)
  	        goto out;
          }
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
}     /* loop ends */
}     /* if ends */


if((emin<=11)&&(emax>=11))
{
output[11]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	     output[9]=charset[t];
	      for(u=start;u<=stop;u++)
	      {
	       output[10]=charset[u];
	       hash_func(output,hashout,11);
           comp = strncmp(hashin,hashout,CMPLVL);
	       if(comp==0)
           {
  	         comp = strcmp(hashin,hashout);
  	         if(comp==0)
  	         goto out;
           }
	      }
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
}  /* loop ends */
}  /* if ends */


if((emin<=12)&&(emax>=12))
{
output[12]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	     output[9]=charset[t];
	      for(u=start;u<=stop;u++)
	      {
	      output[10]=charset[u];
	       for(v=start;v<=stop;v++)
	       {
	        output[11]=charset[v];
	        hash_func(output,hashout,12);
            comp = strncmp(hashin,hashout,CMPLVL);
	        if(comp==0)
            {
  	          comp = strcmp(hashin,hashout);
  	          if(comp==0)
  	          goto out;
            }
	       }
	      }
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
} /* loop ends */
} /* if ends */

out:
stops = clock();
printf("\n\n\tBruteforcing completed !");
timespent = (double)(stops-starts)/CLOCKS_PER_SEC;
printf("\n\n\n\tTime Taken   =  %f sec",timespent);
printf("\n\n\tLast Output  =  %s",output);
printf("\n\n\tLast Hash    =  %s  ",hashout);
}

getch();	     /* main else if ends */
main();
}            /* function ends */
/*<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<*/



/*>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>*/
/*          HASH  C O M P A R E  2          */
void Hash_Compare_2(int emin,int emax,register int start,register int stop,int cpm,int htyp)
{

typedef struct {      /* hash intake structure */
	char hash[hcat[htyp-1]+1];
}input_struct;

typedef struct {      /* outputting structure */
	char password[MAXLEN+1];
	char hash[hcat[htyp-1]+1];
}output_struct;

input_struct *in;
output_struct *out;

in = (input_struct *) calloc(INTAKELIMIT,sizeof(input_struct));
out = (output_struct *) calloc(INTAKELIMIT,sizeof(output_struct));

if(in==NULL || out==NULL)
{
	header();
	printf("\n\n\tDurvasav BfPC [Version %s]",VERSION);
	printf("\n\tCopyright (c) 2013 Vishnu M Aiea (Aygent543)");
	textcolor(LIGHTRED);
	printf("\n\n\n\tError : Memory allocation failure !");
	textcolor(LIGHTGRAY);
	printf("\n\n\tProgram will be terminated now. Press any key ");
	getch();
	exit(1);
}


FILE *fp;
void (*hash_func)();
register unsigned int limit; //no. of hashes read
register unsigned int x, y, v, u, t, s, r, q, p, n, m, k, j, i;
char hashout[hcat[htyp-1]+1];
char hashin[hcat[htyp-1]+1];  /* used as a temp hash array */
static char output[MAXLEN+1];
char filename[FNAMELEN+1];
register int comp;
register int count;
char a ='0';
char hash_type[7]; //stores the name of hash
clock_t starts,stops;  /* stopwatch variables */
double timespent;
static char charset[CSTLIMIT+1]="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+-,.'`/:@;<>?=[]^_{}~|";  /* characterset */
charset[92]='\\';   /* backslash */
charset[93]='\"';   /* double quote */
charset[94]='\0';
clrscr();


switch(htyp)
{
	case 1:
		hash_func = MD4_Convert;
		strcpy(hash_type,"MD4");
		break;
	case 2:
		hash_func = MD5_Convert;
		strcpy(hash_type,"MD5");
		break;
	case 3:
		hash_func = SHA0_Convert;
		strcpy(hash_type,"SHA0");
		break;
	case 4:
		hash_func = SHA1_Convert;
		strcpy(hash_type,"SHA1");
		break;
	case 5:
		hash_func = SHA224_Convert;
		strcpy(hash_type,"SHA224");
		break;
	case 6:
		hash_func = SHA256_Convert;
		strcpy(hash_type,"SHA256");
		break;
	case 7:
		hash_func = SHA384_Convert;
		strcpy(hash_type,"SHA384");
		break;
	case 8:
		hash_func = SHA512_Convert;
		strcpy(hash_type,"SHA512");
		break;
}


if(cpm==1)   /* redefines characterset */
{
	strcpy(charset,"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");  
}


/*******************************************************/
/*               CUSTOM CHARSET                        */
if(cpm==2)
{
	fp = fopen("CUSTOM.CST","r");
	fgets(charset,CSTLIMIT+1,fp);
	charset[(strlen(charset)-1)] = '\0';
	fclose(fp);
	
	start = 0;
	stop = (strlen(charset))-1;
}
/*******************************************************/


header();
printf("\n\n\n\t%s : Compare",hash_type);

if(cpm==2)
{
	printf(" - Custom charset.");
}
else
{
	landing(start,stop,cpm); /* to show where you've landed */
}


printf("\n\n\tInput filename : "); /* inputting hash file */
scanf("%s",filename);

if(filename[0]=='0' && strlen(filename)<2)
{
	main();
}

if(filename[0]=='9' && strlen(filename)<2)
{
	about();
}


printf("\n\tOutput filename : output.txt");

if(strlen(filename)!=0)
{
	fp = fopen(filename,"r");
	if(fp==NULL)
	{
		textcolor(LIGHTRED);
		printf("\n\n\tThe file you asked does not exist ! ");
		textcolor(LIGHTGRAY);
		free(in); //preventing stack overflow
		free(out);
		getch();
		main();
	}
	else
	{
		count=0;
		hashin[0]='\0';
		do
		{
			fscanf(fp,"%s",hashin); /* counting the hashes in file */
			if(strlen(hashin)==hcat[htyp-1])
			{
				hashin[hcat[htyp-1]]='\0';
				count++;
			}
    	}while(!feof(fp));
    	
    	if(count==-1 || count==0)  /* error situation */
    	{
    		textcolor(LIGHTRED);
    		printf("\n\n\tError [E-612] : Invalid input file ! ");
    		textcolor(LIGHTGRAY);
    		free(in); //preventing stack overflow
			free(out);
    		getch();
    		exit(1);
    	}
    	else
    	{
    		fclose(fp);
    		printf("\n\n\tTotal no. of hashes = %d",count-1);
    		limit = count-1;  /* total no. of hashes */
    		
    		if(limit>INTAKELIMIT)
    		{
				printf("\n\n\n\tThat's too large to handle ! Maximum is %d. ",INTAKELIMIT);
				free(in); //preventing stack overflow
				free(out);
				getch();
				main();
			}
    		
    		fp = fopen(filename,"r");
    		
    		for(x=0;x<limit;x++)   /* reading each hash from file */
    		{
    			if(x==INTAKELIMIT)
    			{
    				break;
    			}
    			
    			fscanf(fp,"%s", in[x].hash);  /* to the stuct */
    		}
    		fclose(fp);
    	}

    }
}

printf("\n\n\tTotal no. of combinations = %d^%d",stop-start+1,emax);
printf("\n\n\n\tStart Bruteforcing ?  (Y / N) ");
a=getche();

if(a=='n'||a=='N')
{
	main();
}
else if(a=='y'||a=='Y'||a=='1')    /* main else if */
{
printf("    Please wait... ");

count=0;
starts = clock();

if((emin<=2)&&(emax>=2))
{
output[2]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
 hash_func(output,hashout,2);
   for(x=0;x<limit;x++) /* compare each hash and store to struct if found */
   {
 	 comp = strncmp(in[x].hash,hashout,CMPLVL);
 	 if(comp==0)
 	 {
 	 	comp = strcmp(in[x].hash,hashout);
 	 	if(comp==0)
 	 	{
 	 	  printf("\n\n\t%s - %s ",hashout,output);
 		  strcpy(out[x].hash,hashout);
 		  strcpy(out[x].password,output);
 		  count++;
 		  if(count==limit) /* checking for the limit */
 	 	  goto out;
 	    }
 	 }	 
   }
 }
}    /* loop ends */
}    /* if ends */


if((emin<=3)&&(emax>=3))
{
output[3]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
  hash_func(output,hashout,3);
   for(x=0;x<limit;x++)
   {
 	 comp = strncmp(in[x].hash,hashout,CMPLVL);
 	 if(comp==0)
 	 {
 	 	comp = strcmp(in[x].hash,hashout);
 	 	if(comp==0)
 	 	{
 		  printf("\n\n\t%s - %s ",hashout,output);
		  strcpy(out[x].hash,hashout);
 		  strcpy(out[x].password,output);
 		  count++;
 		  if(count==limit)
 	 	  goto out;
        }
 	 }	 
   }
  }
 }
} /* loop ends */
} /* if ends */


if((emin<=4)&&(emax>=4))
{
output[4]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
   hash_func(output,hashout,4);
    for(x=0;x<limit;x++)
    {
 	  comp = strncmp(in[x].hash,hashout,CMPLVL);
 	  if(comp==0)
 	  {
 	  	comp = strcmp(in[x].hash,hashout);
 	 	if(comp==0)
 	 	{
 		  printf("\n\n\t%s - %s ",hashout,output);
		  strcpy(out[x].hash,hashout);
 		  strcpy(out[x].password,output);
 		  count++;
 		  if(count==limit)
 	 	  goto out;
 	    }
 	  }	 
    }
   }
  }
 }
}      /* loop ends */
}      /* if ends */


if((emin<=5)&&(emax>=5))
{
output[5]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
    hash_func(output,hashout,5);
     for(x=0;x<limit;x++)
     {
 	   comp = strncmp(in[x].hash,hashout,CMPLVL);
 	   if(comp==0)
 	   {
 	   	 comp = strcmp(in[x].hash,hashout);
 	 	 if(comp==0)
 	 	 {
 	   	   printf("\n\n\t%s - %s ",hashout,output);
 		   strcpy(out[x].hash,hashout);
 		   strcpy(out[x].password,output);
 		   count++;
 		   if(count==limit)
 	 	   goto out;
 	     } 
 	   }	 
     }
    }
   }
  }
 }
}    /* loop ends */
}    /* if ends */


if((emin<=6)&&(emax>=6))
{
output[6]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
     hash_func(output,hashout,6);
      for(x=0;x<limit;x++)
      {
 	    comp = strncmp(in[x].hash,hashout,CMPLVL);
 	    if(comp==0)
 	    {
 	      comp = strcmp(in[x].hash,hashout);
 	 	  if(comp==0)
 	 	  {
 	        printf("\n\n\t%s - %s ",hashout,output);
 		    strcpy(out[x].hash,hashout);
 		    strcpy(out[x].password,output);
 		    count++;
 		    if(count==limit)
 	 	    goto out;
 	      }
 	    }	 
      }
     }
    }
   }
  }
 }
}    /* loop ends */
}    /* if ends */


if((emin<=7)&&(emax>=7))
{
output[7]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
      hash_func(output,hashout,7);
       for(x=0;x<limit;x++)
       {
 	     comp = strncmp(in[x].hash,hashout,CMPLVL);
 	     if(comp==0)
 	     {
 	       comp = strcmp(in[x].hash,hashout);
 	 	   if(comp==0)
 	 	   {
 	         printf("\n\n\t%s - %s ",hashout,output);
 		     strcpy(out[x].hash,hashout);
 		     strcpy(out[x].password,output);
 		     count++;
 		     if(count==limit)
 	 	     goto out;
 	 	   }
 	     }	 
       }
      }
     }
    }
   }
  }
 }
}  /* loop ends */
}  /* if ends */


if((emin<=8)&&(emax>=8))
{
output[8]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
       hash_func(output,hashout,8);
        for(x=0;x<limit;x++)
        {
 	      comp = strncmp(in[x].hash,hashout,CMPLVL);
 	      if(comp==0)
 	      {
 	      	comp = strcmp(in[x].hash,hashout);
 	 	    if(comp==0)
 	 	    {
 	      	  printf("\n\n\t%s - %s ",hashout,output);
 		      strcpy(out[x].hash,hashout);
 		      strcpy(out[x].password,output);
 		      count++;
 		      if(count==limit)
 	 	      goto out;
 	 	    }
 	      }	 
        }
       }
      }
     }
    }
   }
  }
 }
}   /* loop ends */
}   /* if ends */


if((emin<=9)&&(emax>=9))
{
output[9]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	     output[8]=charset[s];
	     hash_func(output,hashout,9);
          for(x=0;x<limit;x++)
          {
 	        comp = strncmp(in[x].hash,hashout,CMPLVL);
 	        if(comp==0)
 	        {
 	          comp = strcmp(in[x].hash,hashout);
 	 	      if(comp==0)
 	 	      {
 	            printf("\n\n\t%s - %s ",hashout,output);
 		        strcpy(out[x].hash,hashout);
 		        strcpy(out[x].password,output);
 		        count++;
 		        if(count==limit)
 	 	        goto out;
 	 	      }
 	        }	 
          }
	    }
       }
      }
     }
    }
   }
  }
 }
}   /* loop ends */
}   /* if ends */


if((emin<=10)&&(emax>=10))
{
output[10]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	     output[9]=charset[t];
	     hash_func(output,hashout,10);
          for(x=0;x<limit;x++)
          {
 	        comp = strncmp(in[x].hash,hashout,CMPLVL);
 	        if(comp==0)
 	        {
 	          comp = strcmp(in[x].hash,hashout);
 	 	      if(comp==0)
 	 	      {
 	            printf("\n\n\t%s - %s ",hashout,output);
 		        strcpy(out[x].hash,hashout);
 		        strcpy(out[x].password,output);
 		        count++;
 		        if(count==limit)
 	 	        goto out;
 	          }	 
 	        }
          }
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
}     /* loop ends */
}     /* if ends */


if((emin<=11)&&(emax>=11))
{
output[11]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	     output[9]=charset[t];
	      for(u=start;u<=stop;u++)
	      {
	      output[10]=charset[u];
	      hash_func(output,hashout,11);
           for(x=0;x<limit;x++)
           {
 	         comp = strncmp(in[x].hash,hashout,CMPLVL);
 	         if(comp==0)
 	         {
 	           comp = strcmp(in[x].hash,hashout);
 	 	       if(comp==0)
 	 	       {
 	             printf("\n\n\t%s - %s ",hashout,output);
 		         strcpy(out[x].hash,hashout);
 		         strcpy(out[x].password,output);
 		         count++;
 		         if(count==limit)
 	 	         goto out;
 	 	       }
 	         }	 
           }
	      }
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
}  /* loop ends */
}  /* if ends */


if((emin<=12)&&(emax>=12))
{
output[12]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	     output[9]=charset[t];
	      for(u=start;u<=stop;u++)
	      {
	      output[10]=charset[u];
	       for(v=start;v<=stop;v++)
	       {
	       output[11]=charset[v];
	       hash_func(output,hashout,12);
            for(x=0;x<limit;x++)
            {
 	          comp = strncmp(in[x].hash,hashout,CMPLVL);
 	          if(comp==0)
 	          {
 	          	comp = strcmp(in[x].hash,hashout);
 	 	        if(comp==0)
 	 	        {
 	          	  printf("\n\n\t%s - %s ",hashout,output);
 		          strcpy(out[x].hash,hashout);
 		          strcpy(out[x].password,output);
 		          count++;
 		          if(count==limit)
 	 	          goto out;
 	 	        }
 	          }	 
            }
	       }
	      }
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
} /* loop ends */
} /* if ends */

out:    /* label for jumping from heavy nested loops */
stops = clock();

fp = fopen("OUTPUT.TXT","w");
fprintf(fp,"Output file of cracked %s hashes by DURVASAV v%s\n\n",hash_type,VERSION);

for(x=0;x<limit;x++)
{
	fprintf(fp,"%s",out[x].hash);  /* writing hashes */
	if(strlen(out[x].password)==0)  /* when password not foud in search!*/
	{
		fprintf(fp,"  - Not Found\n");
	}
	else
	{
		fprintf(fp,"  - %s\n",out[x].password);
	}
}
fclose(fp);

printf("\n\n\tBruteforcing completed !");
timespent = (double)(stops-starts)/CLOCKS_PER_SEC;
printf("\n\n\n\tTime Taken   =  %f sec",timespent);
printf("\n\n\tLast Output  =  %s",output);
printf("\n\n\tLast Hash    =  %s  ",hashout);
}

free(in); //preventing stack overflow
free(out);

getch();	     /* main else if ends */
main();
}            /* function ends */
/*<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<*/



/*>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>*/
/*          HASH  P R I N T                 */
void Hash_Print(int emin,int emax,register int start,register int stop,int cpm,int htyp)
{
FILE *fp;
void (* hash_func)();
register unsigned int v, u, t, s, r, q, p, n, m, k, j, i;
char hashout[hcat[htyp-1]+1];
static char output[MAXLEN+1];
char a;
char hash_type[7];
clock_t starts,stops;
double timespent;
static char charset[CSTLIMIT+1]="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+-,.'`/:@;<>?=[]^_{}~|";  /* characterset */
charset[92]='\\';   /* backslash */
charset[93]='\"';   /* double quote */
charset[94]='\0';
clrscr();


switch(htyp)
{
	case 1:
		hash_func = MD4_Convert;
		strcpy(hash_type,"MD4");
		break;
	case 2:
		hash_func = MD5_Convert;
		strcpy(hash_type,"MD5");
		break;
	case 3:
		hash_func = SHA0_Convert;
		strcpy(hash_type,"SHA0");
		break;
	case 4:
		hash_func = SHA1_Convert;
		strcpy(hash_type,"SHA1");
		break;
	case 5:
		hash_func = SHA224_Convert;
		strcpy(hash_type,"SHA224");
		break;
	case 6:
		hash_func = SHA256_Convert;
		strcpy(hash_type,"SHA256");
		break;
	case 7:
		hash_func = SHA384_Convert;
		strcpy(hash_type,"SHA384");
		break;
	case 8:
		hash_func = SHA512_Convert;
		strcpy(hash_type,"SHA512");
		break;
}


if(cpm==1)
{
	strcpy(charset,"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
}


/*******************************************************/
/*               CUSTOM CHARSET                        */
if(cpm==2)
{
	fp = fopen("CUSTOM.CST","r");
	fgets(charset,CSTLIMIT+1,fp);
	charset[(strlen(charset)-1)] = '\0';
	fclose(fp);
	
	start = 0;
	stop = (strlen(charset))-1;
}
/*******************************************************/


header();
printf("\n\n\n\n\t%s : Print",hash_type);

if(cpm==2)
{
	printf(" - Custom charset.");
}
else
{
	landing(start,stop,cpm);
}


printf("\n\n\tTotal no. of combinations = %d^%d",stop-start+1,emax);
printf("\n\n\n\tStart Bruteforcing ?  (Y / N) ");
a=getche();

if(a=='n'||a=='N')
{
	main();
}
else if(a=='y'||a=='Y'||a=='1')    /* main else if */
{
printf("    Please wait... ");
printf("\n\n\n");

starts = clock();

if((emin<=2)&&(emax>=2))
{
output[2]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
  output[1]=charset[j];
  hash_func(output,hashout,2);
  printf("\t%s\n",hashout);
 }
}    /* loop ends */
}    /* if ends */


if((emin<=3)&&(emax>=3))
{
output[3]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
   output[2]=charset[k];
   hash_func(output,hashout,3);
   printf("\t%s\n",hashout);
  }
 }
} /* loop ends */
} /* if ends */


if((emin<=4)&&(emax>=4))
{
output[4]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
    output[3]=charset[m];
    hash_func(output,hashout,4);
    printf("\t%s\n",hashout);
   }
  }
 }
}      /* loop ends */
}      /* if ends */


if((emin<=5)&&(emax>=5))
{
output[5]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
     output[4]=charset[n];
     hash_func(output,hashout,5);
     printf("\t%s\n",hashout);
    }
   }
  }
 }
}    /* loop ends */
}    /* if ends */


if((emin<=6)&&(emax>=6))
{
output[6]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
      output[5]=charset[p];
      hash_func(output,hashout,6);
      printf("\t%s\n",hashout);
     }
    }
   }
  }
 }
}    /* loop ends */
}    /* if ends */


if((emin<=7)&&(emax>=7))
{
output[7]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
       output[6]=charset[q];
       hash_func(output,hashout,7);
       printf("\t%s\n",hashout);
      }
     }
    }
   }
  }
 }
}  /* loop ends */
}  /* if ends */


if((emin<=8)&&(emax>=8))
{
output[8]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
        output[7]=charset[r];
        hash_func(output,hashout,8);
        printf("\t%s\n",hashout);
       }
      }
     }
    }
   }
  }
 }
}   /* loop ends */
}   /* if ends */


if((emin<=9)&&(emax>=9))
{
output[9]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	     output[8]=charset[s];
	     hash_func(output,hashout,9);
	     printf("\t%s\n",hashout);
	    }
       }
      }
     }
    }
   }
  }
 }
}   /* loop ends */
}   /* if ends */


if((emin<=10)&&(emax>=10))
{
output[10]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	      output[9]=charset[t];
	      hash_func(output,hashout,10);
	      printf("\t%s\n",hashout);
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
}     /* loop ends */
}     /* if ends */


if((emin<=11)&&(emax>=11))
{
output[11]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	     output[9]=charset[t];
	      for(u=start;u<=stop;u++)
	      {
	       output[10]=charset[u];
	       hash_func(output,hashout,11);
	       printf("\t%s\n",hashout);
	      }
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
}  /* loop ends */
}  /* if ends */


if((emin<=12)&&(emax>=12))
{
output[12]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	     output[9]=charset[t];
	      for(u=start;u<=stop;u++)
	      {
	      output[10]=charset[u];
	       for(v=start;v<=stop;v++)
	       {
	        output[11]=charset[v];
	        hash_func(output,hashout,12);
	        printf("\t%s\n",hashout);
	       }
	      }
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
} /* loop ends */
} /* if ends */

stops = clock();
printf("\n\n\tBruteforcing completed !");
timespent = (double)(stops-starts)/CLOCKS_PER_SEC;
printf("\n\n\n\tTime Taken   =  %f sec",timespent);
printf("\n\n\tLast Output  =  %s",output);
printf("\n\n\tLast Hash    =  %s\n\t",hashout);
}

getch();	     /* main else if ends */
main();
}            /* function ends */
/*<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<*/



/*>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>*/
/*       HASH  WORDLIST  FILE  OUTPUT      */
void Hash_Fout(int emin,int emax,register int start,register int stop,int cpm,int htyp)
{
FILE *fp;
void (* hash_func)();
register unsigned int v, u, t, s, r, q, p, n, m, k, j, i;
char hashout[hcat[htyp-1]+1];
static char output[MAXLEN+1];
char a;
char hash_type[7];
clock_t starts,stops;
double timespent;
static char charset[CSTLIMIT+1]="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+-,.'`/:@;<>?=[]^_{}~|";  /* characterset */
charset[92]='\\';   /* backslash */
charset[93]='\"';   /* double quote */
charset[94]='\0';
clrscr();


switch(htyp)
{
	case 1:
		hash_func = MD4_Convert;
		strcpy(hash_type,"MD4");
		break;
	case 2:
		hash_func = MD5_Convert;
		strcpy(hash_type,"MD5");
		break;
	case 3:
		hash_func = SHA0_Convert;
		strcpy(hash_type,"SHA0");
		break;
	case 4:
		hash_func = SHA1_Convert;
		strcpy(hash_type,"SHA1");
		break;
	case 5:
		hash_func = SHA224_Convert;
		strcpy(hash_type,"SHA224");
		break;
	case 6:
		hash_func = SHA256_Convert;
		strcpy(hash_type,"SHA256");
		break;
	case 7:
		hash_func = SHA384_Convert;
		strcpy(hash_type,"SHA384");
		break;
	case 8:
		hash_func = SHA512_Convert;
		strcpy(hash_type,"SHA512");
		break;
}


if(cpm==1)
{
	strcpy(charset,"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
}


/*******************************************************/
/*               CUSTOM CHARSET                        */
if(cpm==2)
{
	fp = fopen("CUSTOM.CST","r");
	fgets(charset,CSTLIMIT+1,fp);
	charset[(strlen(charset)-1)] = '\0';
	fclose(fp);
	
	start = 0;
	stop = (strlen(charset))-1;
}
/*******************************************************/


header();
printf("\n\n\n\n\t%s : File Output",hash_type);

if(cpm==2)
{
	printf(" - Custom charset.");
}
else
{
	landing(start,stop,cpm);
}


printf("\n\n\tOutput file : wordlist.txt");
printf("\n\n\tTotal no. of combinations = %d^%d",stop-start+1,emax);
printf("\n\n\n\tStart Bruteforcing ?  (Y / N) ");
a=getche();

if(a=='n'||a=='N')
{
	main();
}
else if(a=='y'||a=='Y'||a=='1')    /* main else if */
{
printf("    Please wait... ");

fp=fopen("WORDLIST.TXT","w");

if(fp==NULL)
{
	textcolor(LIGHTRED);
	printf("\n\n\tError [E-675w] : File could not be opened ! ");
	textcolor(LIGHTGRAY);
	getch();
	exit(1);
}

fprintf(fp,"%s hashes of %d^%d by DURVASAV_v%s\n\n",hash_type,stop-start+1,emax,VERSION);

starts = clock();

if((emin<=2)&&(emax>=2))
{
output[2]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
  output[1]=charset[j];
  hash_func(output,hashout,2);
  fprintf(fp,"%s\n",hashout);
 }
}    /* loop ends */
}    /* if ends */


if((emin<=3)&&(emax>=3))
{
output[3]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
   output[2]=charset[k];
   hash_func(output,hashout,3);
   fprintf(fp,"%s\n",hashout);
  }
 }
} /* loop ends */
} /* if ends */


if((emin<=4)&&(emax>=4))
{
output[4]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
    output[3]=charset[m];
    hash_func(output,hashout,4);
    fprintf(fp,"%s\n",hashout);
   }
  }
 }
}      /* loop ends */
}      /* if ends */


if((emin<=5)&&(emax>=5))
{
output[5]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
     output[4]=charset[n];
     hash_func(output,hashout,5);
     fprintf(fp,"%s\n",hashout);
    }
   }
  }
 }
}    /* loop ends */
}    /* if ends */


if((emin<=6)&&(emax>=6))
{
output[6]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
      output[5]=charset[p];
      hash_func(output,hashout,6);
      fprintf(fp,"%s\n",hashout);
     }
    }
   }
  }
 }
}    /* loop ends */
}    /* if ends */


if((emin<=7)&&(emax>=7))
{
output[7]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
       output[6]=charset[q];
       hash_func(output,hashout,7);
       fprintf(fp,"%s\n",hashout);
      }
     }
    }
   }
  }
 }
}  /* loop ends */
}  /* if ends */


if((emin<=8)&&(emax>=8))
{
output[8]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
        output[7]=charset[r];
        hash_func(output,hashout,8);
        fprintf(fp,"%s\n",hashout);
       }
      }
     }
    }
   }
  }
 }
}   /* loop ends */
}   /* if ends */


if((emin<=9)&&(emax>=9))
{
output[9]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	     output[8]=charset[s];
	     hash_func(output,hashout,9);
	     fprintf(fp,"%s\n",hashout);
	    }
       }
      }
     }
    }
   }
  }
 }
}   /* loop ends */
}   /* if ends */


if((emin<=10)&&(emax>=10))
{
output[10]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	      output[9]=charset[t];
	      hash_func(output,hashout,10);
	      fprintf(fp,"%s\n",hashout);
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
}     /* loop ends */
}     /* if ends */


if((emin<=11)&&(emax>=11))
{
output[11]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	     output[9]=charset[t];
	      for(u=start;u<=stop;u++)
	      {
	       output[10]=charset[u];
	       hash_func(output,hashout,11);
	      fprintf(fp,"%s\n",hashout);
	      }
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
}  /* loop ends */
}  /* if ends */


if((emin<=12)&&(emax>=12))
{
output[12]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	     output[9]=charset[t];
	      for(u=start;u<=stop;u++)
	      {
	      output[10]=charset[u];
	       for(v=start;v<=stop;v++)
	       {
	        output[11]=charset[v];
	        hash_func(output,hashout,12);
	        fprintf(fp,"%s\n",hashout);
	       }
	      }
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
} /* loop ends */
} /* if ends */

stops = clock();
fclose(fp);
printf("\n\n\tBruteforcing completed !");
timespent = (double)(stops-starts)/CLOCKS_PER_SEC;
printf("\n\n\n\tTime Taken   =  %f sec",timespent);
printf("\n\n\tLast Output  =  %s",output);
printf("\n\n\tLast Hash    =  %s ",hashout);

} /* main else if ends */

getch();
main();
}            /* function ends */
/*<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<*/



/*>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>*/
/*          PSEUDO  P E R F O R M             */
void Pseudo_Perform(int emin,int emax,register int start,register int stop,int pm,int htyp)
{
FILE *fp;	
register unsigned int v, u, t, s, r, q, p, n, m, k, j, i;
static char output[MAXLEN+1];
char a;
clock_t starts,stops;
double timespent;
static char charset[CSTLIMIT+1]="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+-,.'`/:@;<>?=[]^_{}~|";  /* characterset */
charset[92]='\\';   /* backslash */
charset[93]='\"';   /* double quote */
charset[94]='\0';
clrscr();


if(pm==1)
{
	strcpy(charset,"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
}


/*******************************************************/
/*               CUSTOM CHARSET                        */
if(pm==2)
{
	fp = fopen("CUSTOM.CST","r");
	fgets(charset,CSTLIMIT+1,fp);
	charset[(strlen(charset)-1)] = '\0';
	fclose(fp);
	
	start = 0;
	stop = (strlen(charset))-1;
}
/*******************************************************/


header();
printf("\n\n\n\n\tPseudo : Perform");

if(pm==2)
{
	printf(" - Custom charset.");
}
else
{
	landing(start,stop,pm);
}


printf("\n\n\tTotal no. of combinations = %d^%d",stop-start+1,emax);
printf("\n\n\n\tStart Bruteforcing ?  (Y / N) ");
a=getche();

if(a=='n'||a=='N')
{
	main();
}
else if(a=='y'||a=='Y'||a=='1')    /* main else if */
{
printf("    Please wait... ");
starts = clock();  /* stopwatch starts */

if((emin<=2)&&(emax>=2))    /* execution condition */
{
output[2]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
  output[1]=charset[j];
 }
}    /* loop ends */
}    /* if ends */


if((emin<=3)&&(emax>=3))
{
output[3]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
   output[2]=charset[k];
  }
 }
} /* loop ends */
} /* if ends */


if((emin<=4)&&(emax>=4))
{
output[4]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
    output[3]=charset[m];
   }
  }
 }
}      /* loop ends */
}      /* if ends */


if((emin<=5)&&(emax>=5))
{
output[5]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
     output[4]=charset[n];
    }
   }
  }
 }
}    /* loop ends */
}    /* if ends */


if((emin<=6)&&(emax>=6))
{
output[6]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
      output[5]=charset[p];
     }
    }
   }
  }
 }
}    /* loop ends */
}    /* if ends */


if((emin<=7)&&(emax>=7))
{
output[7]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
       output[6]=charset[q];
      }
     }
    }
   }
  }
 }
}   /* loop ends */
}   /* if ends */


if((emin<=8)&&(emax>=8))
{
output[8]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
        output[7]=charset[r];
       }
      }
     }
    }
   }
  }
 }
}   /* loop ends */
}   /* if ends */


if((emin<=9)&&(emax>=9))
{
output[9]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	     output[8]=charset[s];
	    }
       }
      }
     }
    }
   }
  }
 }
}   /* loop ends */
}   /* if ends */


if((emin<=10)&&(emax>=10))
{
output[10]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	      output[9]=charset[t];
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
}     /* loop ends */
}     /* if ends */


if((emin<=11)&&(emax>=11))
{
output[11]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	     output[9]=charset[t];
	      for(u=start;u<=stop;u++)
	      {
	       output[10]=charset[u];
	      }
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
}  /* loop ends */
}  /* if ends */


if((emin<=12)&&(emax>=12))
{
output[12]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	     output[9]=charset[t];
	      for(u=start;u<=stop;u++)
	      {
	      output[10]=charset[u];
	       for(v=start;v<=stop;v++)
	       {
	        output[11]=charset[v];
	       }
	      }
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
}   /* loop ends */
}   /*  if ends */

stops = clock();
printf("\n\n\tBruteforcing completed !");
timespent = (double)(stops-starts)/CLOCKS_PER_SEC; /* calculating time taken */
printf("\n\n\n\tTime Taken   =  %f sec",timespent);
printf("\n\n\tLast Output  =  %s  ",output);
}

getch();	     /* main else if ends */
main();
}            /* function ends */
/*<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<*/



/*>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>*/
/*          PSEUDO  C O M P A R E             */
void Pseudo_Compare(int emin,int emax,register int start,register int stop,int pm,int htyp)
{
FILE *fp;	
register unsigned int v, u, t, s, r, q, p, n, m, k, j, i;
static char output[MAXLEN+1];
static char string[MAXLEN+1];
register int comp;
char a;
clock_t starts,stops;
double timespent;
static char charset[CSTLIMIT+1]="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+-,.'`/:@;<>?=[]^_{}~|";  /* characterset */
charset[92]='\\';   /* backslash */
charset[93]='\"';   /* double quote */
charset[94]='\0';
clrscr();


if(pm==1)
{
	strcpy(charset,"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");  /* charset redefine */
}


/*******************************************************/
/*               CUSTOM CHARSET                        */
if(pm==2)
{
	fp = fopen("CUSTOM.CST","r");
	fgets(charset,CSTLIMIT+1,fp);
	charset[(strlen(charset)-1)] = '\0';
	fclose(fp);
	
	start = 0;
	stop = (strlen(charset))-1;
}
/*******************************************************/


again:
header();
printf("\n\n\n\n\tPseudo : Compare");

if(pm==2)
{
	printf(" - Custom charset.");
}

else
{
	landing(start,stop,pm);
}


printf("\n\n\tEnter string : ");
scanf("%s",string);

if(string[0]=='0' && strlen(string)<2)   /* exit for zero */
{
	exit(0);
}

else if(string[0]=='9' && strlen(string)<2)   /* about for nine */
{
	about();
}


printf("\n\tTotal no. of combinations = %d^%d",stop-start+1,emax);
printf("\n\n\n\tStart Bruteforcing ?  (Y / N) ");
a=getche();

if(a=='n'||a=='N')
{
	main();
}

else if(a=='y'||a=='Y'||a=='1')    /* main else if */
{
printf("    Please wait... ");

starts = clock();

if((emin<=2)&&(emax>=2))
{
output[2]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
  output[1]=charset[j];
  comp=strcmp(output,string);
  if(comp==0)
  goto out;
 }
}    /* loop ends */
}    /* if ends */


if((emin<=3)&&(emax>=3))
{
output[3]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
   output[2]=charset[k];
   comp=strcmp(output,string);
   if(comp==0)
   goto out;
  }
 }
} /* loop ends */
} /* if ends */


if((emin<=4)&&(emax>=4))
{
output[4]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
    output[3]=charset[m];
    comp=strcmp(output,string);
    if(comp==0)
    goto out;
   }
  }
 }
}      /* loop ends */
}      /* if ends */


if((emin<=5)&&(emax>=5))
{
output[5]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
     output[4]=charset[n];
     comp=strcmp(output,string);
     if(comp==0)
     goto out;
    }
   }
  }
 }
}    /* loop ends */
}    /* if ends */


if((emin<=6)&&(emax>=6))
{
output[6]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
      output[5]=charset[p];
      comp=strcmp(output,string);
      if(comp==0)
      goto out;
     }
    }
   }
  }
 }
}    /* loop ends */
}    /* if ends */


if((emin<=7)&&(emax>=7))
{
output[7]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
       output[6]=charset[q];
       comp=strcmp(output,string);
       if(comp==0)
       goto out;
      }
     }
    }
   }
  }
 }
}  /* loop ends */
}  /* if ends */


if((emin<=8)&&(emax>=8))
{
output[8]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
        output[7]=charset[r];
        comp=strcmp(output,string);
        if(comp==0)
        goto out;
       }
      }
     }
    }
   }
  }
 }
}   /* loop ends */
}   /* if ends */


if((emin<=9)&&(emax>=9))
{
output[9]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	     output[8]=charset[s];
         comp=strcmp(output,string);
	     if(comp==0)
	     goto out;
	    }
       }
      }
     }
    }
   }
  }
 }
}   /* loop ends */
}   /* if ends */


if((emin<=10)&&(emax>=10))
{
output[10]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	      output[9]=charset[t];
          comp=strcmp(output,string);
	      if(comp==0)
	      goto out;
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
}     /* loop ends */
}     /* if ends */


if((emin<=11)&&(emax>=11))
{
output[11]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	     output[9]=charset[t];
	      for(u=start;u<=stop;u++)
	      {
	       output[10]=charset[u];
           comp=strcmp(output,string);
	       if(comp==0)
	       goto out;
	      }
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
}  /* loop ends */
}  /* if ends */


if((emin<=12)&&(emax>=12))
{
output[12]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	     output[9]=charset[t];
	      for(u=start;u<=stop;u++)
	      {
	      output[10]=charset[u];
	       for(v=start;v<=stop;v++)
	       {
	        output[11]=charset[v];
            comp=strcmp(output,string);
	        if(comp==0)
	        goto out;
	       }
	      }
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
} /* loop ends */
} /* if ends */

out:
stops = clock();
printf("\n\n\tBruteforcing completed !");
timespent = (double)(stops-starts)/CLOCKS_PER_SEC;
printf("\n\n\n\tTime Taken   =  %f sec",timespent);
printf("\n\n\tLast Output  =  %s  ",output);
}

getch();	     /* main else if ends */
main();
}            /* function ends */
/*<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<*/



/*>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>*/
/*          PSEUDO  P R I N T                 */
void Pseudo_Print(int emin,int emax,register int start,register int stop,int pm,int htyp)
{
FILE *fp;	
register unsigned int v, u, t, s, r, q, p, n, m, k, j, i;
static char output[MAXLEN+1];
char a;
clock_t starts,stops;
double timespent;
static char charset[CSTLIMIT+1]="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+-,.'`/:@;<>?=[]^_{}~|";  /* characterset */
charset[92]='\\';   /* backslash */
charset[93]='\"';   /* double quote */
charset[94]='\0';
clrscr();


if(pm==1)
{
	strcpy(charset,"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
}


/*******************************************************/
/*               CUSTOM CHARSET                        */
if(pm==2)
{
	fp = fopen("CUSTOM.CST","r");
	fgets(charset,CSTLIMIT+1,fp);
	charset[(strlen(charset)-1)] = '\0';
	fclose(fp);
	
	start = 0;
	stop = (strlen(charset))-1;
}
/*******************************************************/


header();
printf("\n\n\n\n\tPseudo : Print");

if(pm==2)
{
	printf(" - Custom charset.");
}
else
{
	landing(start,stop,pm);
}


printf("\n\n\tTotal no. of combinations = %d^%d",stop-start+1,emax);
printf("\n\n\n\tStart Bruteforcing ?  (Y / N) ");
a=getche();
if(a=='n'||a=='N')
{
	main();
}
else if(a=='y'||a=='Y'||a=='1')    /* main else if */
{
printf("    Please wait... ");
printf("\n\n\n");

starts = clock();

if((emin<=2)&&(emax>=2))
{
output[2]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
 printf("\t%s\n",output);
 }
}    /* loop ends */
}    /* if ends */


if((emin<=3)&&(emax>=3))
{
output[3]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
   output[2]=charset[k];
   printf("\t%s\n",output);
  }
 }
} /* loop ends */
} /* if ends */


if((emin<=4)&&(emax>=4))
{
output[4]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
    output[3]=charset[m];
    printf("\t%s\n",output);
   }
  }
 }
}      /* loop ends */
}      /* if ends */


if((emin<=5)&&(emax>=5))
{
output[5]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
     output[4]=charset[n];
     printf("\t%s\n",output);
    }
   }
  }
 }
}    /* loop ends */
}    /* if ends */


if((emin<=6)&&(emax>=6))
{
output[6]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
      output[5]=charset[p];
      printf("\t%s\n",output);
     }
    }
   }
  }
 }
}    /* loop ends */
}    /* if ends */


if((emin<=7)&&(emax>=7))
{
output[7]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
       output[6]=charset[q];
       printf("\t%s\n",output);
      }
     }
    }
   }
  }
 }
}  /* loop ends */
}  /* if ends */


if((emin<=8)&&(emax>=8))
{
output[8]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
        output[7]=charset[r];
        printf("\t%s\n",output);
       }
      }
     }
    }
   }
  }
 }
}   /* loop ends */
}   /* if ends */


if((emin<=9)&&(emax>=9))
{
output[9]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	     output[8]=charset[s];
	     printf("\t%s\n",output);
	    }
       }
      }
     }
    }
   }
  }
 }
}   /* loop ends */
}   /* if ends */


if((emin<=10)&&(emax>=10))
{
output[10]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	      output[9]=charset[t];
	      printf("\t%s\n",output);
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
}     /* loop ends */
}     /* if ends */


if((emin<=11)&&(emax>=11))
{
output[11]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	     output[9]=charset[t];
	      for(u=start;u<=stop;u++)
	      {
	       output[10]=charset[u];
	       printf("\t%s\n",output);
	      }
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
}  /* loop ends */
}  /* if ends */


if((emin<=12)&&(emax>=12))
{
output[12]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	     output[9]=charset[t];
	      for(u=start;u<=stop;u++)
	      {
	      output[10]=charset[u];
	       for(v=start;v<=stop;v++)
	       {
	        output[11]=charset[v];
	        printf("\t%s\n",output);
	       }
	      }
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
} /* loop ends */
} /* if ends */

stops = clock();
printf("\n\n\tBruteforcing completed !");
timespent = (double)(stops-starts)/CLOCKS_PER_SEC;
printf("\n\n\n\tTime Taken   =  %f sec",timespent);
printf("\n\n\tLast Output  =  %s\n\t",output);
}

getch();	     /* main else if ends */
main();
}            /* function ends */
/*<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<*/



/*>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>*/
/*    PSEUDO  WORDLIST  FILE  OUTPUT       */
void Pseudo_Fout(int emin,int emax,register int start,register int stop,int pm,int htyp)
{
FILE *fp;
register unsigned int v, u, t, s, r, q, p, n, m, k, j, i;
static char output[MAXLEN+1];
char a;
clock_t starts,stops;
double timespent;
static char charset[CSTLIMIT+1]="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+-,.'`/:@;<>?=[]^_{}~|";  /* characterset */
charset[92]='\\';   /* backslash */
charset[93]='\"';   /* double quote */
charset[94]='\0';
clrscr();


if(pm==1)
{
strcpy(charset,"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
}


/*******************************************************/
/*               CUSTOM CHARSET                        */
if(pm==2)
{
	fp = fopen("CUSTOM.CST","r");
	fgets(charset,CSTLIMIT+1,fp);
	charset[(strlen(charset)-1)] = '\0';
	fclose(fp);
	
	start = 0;
	stop = (strlen(charset))-1;
}
/*******************************************************/


header();
printf("\n\n\n\n\tPseudo : File Output");

if(pm==2)
{
	printf(" - Custom charset.");
}
else
{
	landing(start,stop,pm);
}


printf("\n\n\tOutput file : wordlist.txt");
printf("\n\n\tTotal no. of combinations = %d^%d",stop-start+1,emax);
printf("\n\n\n\tStart Bruteforcing ?  (Y / N) ");
a=getche();
if(a=='n'||a=='N')
{
	main();
}
else if(a=='y'||a=='Y'||a=='1')    /* main else if */
{
printf("    Please wait... ");

fp=fopen("WORDLIST.TXT","w");
if(fp==NULL)
{
 textcolor(LIGHTRED);
 printf("\n\n\tError [E-675w] : File could not be opened ! ");
 textcolor(LIGHTGRAY);
 getch();
 exit(1);
}

fprintf(fp,"Permutation list of %d^%d by DURVASAV_v%s\n\n",stop-start+1,emax,VERSION);

starts = clock();

if((emin<=2)&&(emax>=2))
{
output[2]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
  output[1]=charset[j];
  fprintf(fp,"%s\n",output);
 }
}    /* loop ends */
}    /* if ends */


if((emin<=3)&&(emax>=3))
{
output[3]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
   output[2]=charset[k];
   fprintf(fp,"%s\n",output);
  }
 }
} /* loop ends */
} /* if ends */


if((emin<=4)&&(emax>=4))
{
output[4]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
    output[3]=charset[m];
    fprintf(fp,"%s\n",output);
   }
  }
 }
}      /* loop ends */
}      /* if ends */


if((emin<=5)&&(emax>=5))
{
output[5]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
     output[4]=charset[n];
     fprintf(fp,"%s\n",output);
    }
   }
  }
 }
}    /* loop ends */
}    /* if ends */


if((emin<=6)&&(emax>=6))
{
output[6]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
      output[5]=charset[p];
      fprintf(fp,"%s\n",output);
     }
    }
   }
  }
 }
}    /* loop ends */
}    /* if ends */


if((emin<=7)&&(emax>=7))
{
output[7]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
       output[6]=charset[q];
       fprintf(fp,"%s\n",output);
      }
     }
    }
   }
  }
 }
}  /* loop ends */
}  /* if ends */


if((emin<=8)&&(emax>=8))
{
output[8]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
        output[7]=charset[r];
        fprintf(fp,"%s\n",output);
       }
      }
     }
    }
   }
  }
 }
}   /* loop ends */
}   /* if ends */


if((emin<=9)&&(emax>=9))
{
output[9]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	     output[8]=charset[s];
	     fprintf(fp,"%s\n",output);
	    }
       }
      }
     }
    }
   }
  }
 }
}   /* loop ends */
}   /* if ends */


if((emin<=10)&&(emax>=10))
{
output[10]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	      output[9]=charset[t];
	      fprintf(fp,"%s\n",output);
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
}     /* loop ends */
}     /* if ends */


if((emin<=11)&&(emax>=11))
{
output[11]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	     output[9]=charset[t];
	      for(u=start;u<=stop;u++)
	      {
	       output[10]=charset[u];
	       fprintf(fp,"%s\n",output);
	      }
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
}  /* loop ends */
}  /* if ends */


if((emin<=12)&&(emax>=12))
{
output[12]='\0';
for(i=start;i<=stop;i++)
{
output[0]=charset[i];
 for(j=start;j<=stop;j++)
 {
 output[1]=charset[j];
  for(k=start;k<=stop;k++)
  {
  output[2]=charset[k];
   for(m=start;m<=stop;m++)
   {
   output[3]=charset[m];
    for(n=start;n<=stop;n++)
    {
    output[4]=charset[n];
     for(p=start;p<=stop;p++)
     {
     output[5]=charset[p];
      for(q=start;q<=stop;q++)
      {
      output[6]=charset[q];
       for(r=start;r<=stop;r++)
       {
       output[7]=charset[r];
	    for(s=start;s<=stop;s++)
	    {
	    output[8]=charset[s];
	     for(t=start;t<=stop;t++)
	     {
	     output[9]=charset[t];
	      for(u=start;u<=stop;u++)
	      {
	      output[10]=charset[u];
	       for(v=start;v<=stop;v++)
	       {
	        output[11]=charset[v];
	        fprintf(fp,"%s\n",output);
	       }
	      }
	     }
	    }
       }
      }
     }
    }
   }
  }
 }
} /* loop ends */
} /* if ends */

stops = clock();
fclose(fp);
printf("\n\n\tBruteforcing completed !");
timespent = (double)(stops-starts)/CLOCKS_PER_SEC;
printf("\n\n\n\tTime Taken   =  %f sec",timespent);
printf("\n\n\tLast Output  =  %s  ",output);
}

getch();	     /* main else if ends */
main();
}            /* function ends */
/*<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<*/


/*############################################################################*/
/*############################################################################*/


/*>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>*/
void header()
{
	textcolor(LIGHTRED);
	printf("\n\t\t\t        D U R V A S A V");
	textcolor(YELLOW);
	printf("\n\t\t\t        ---------------");
	printf("\n\t\t\t>>> ");
	textcolor(LIGHTGRAY);
	printf("Bruteforce by Aygent543 ");
	textcolor(YELLOW);
	printf("<<<");
	printf("\n\t\t        -------------------------------");
	textcolor(LIGHTGRAY);
}
/*<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<*/



/*>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>*/
void about()     /* A B O U T */
{
	clrscr();
	textcolor(LIGHTRED);
	printf("\n\n\n\n\n\n\n\t\t\t\tD U R V A S A V");
	textcolor(YELLOW);
	printf("\n\t\t\t\t---------------");
	textcolor(LIGHTGRAY);
	printf("\n\t\t\t  Bruteforce Password Cracker");
	printf("\n\n\t\t\t       Version  %s",VERSION);
	printf("\n\n\n\t\t     Copyright (c) 2013  by  Vishnu M Aiea");
	printf("\n\n\n\t\t             vishnumaiea@gmail.com");
	printf("\n\n\t\t               www.durvasav.net   ");
	getch();
	main();
}
/*<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<*/



/*<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<*/
void landing(int start, int stop,int pm)
{
	if(start==0 && stop==9)
	{
		printf(" - [0..9] charset.");
	}
	else if(start==10 && stop==35)
	{
		printf(" - [a...z] charset.");
	}
	else if(start==36 && stop==61)
	{
		printf(" - [A...Z] charset.");
	}
	else if(start==0 && stop==35 && pm==0)
	{
		printf(" - [0...z] charset.");
	}
	else if(start==0 && stop==35 && pm==1)
	{
		printf(" - [0...Z] charset.");
	}
	else if(start==10 && stop==61)
	{
		printf(" - [a...Z] charset.");
	}
	else if(start==0 && stop==61)
	{
		printf(" - [0..a..Z] charset.");
	}
	else if (start==0 && stop==93)
	{
		printf(" - [0..a..Z..#] charset.");
	}
}
/*<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<*/

/*############################################################################*/
/*############################################################################*/

