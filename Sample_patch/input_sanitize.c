/* reference checking file permissions - https://unix.stackexchange.com/questions/82347/how-to-check-if-a-user-can-access-a-given-file
http://www.sanfoundry.com/chroot-command-usage-examples-linux/
*/
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
int sanitize(char *word) //1-success
{
int i=0;
char c;
char chrootcmd[50]="";
//checking character by character
while(word[i]!='\0')
{
	c=word[i];
	label2: switch(c){
	//format string vulnerability
	case '%':
		i++;
		c=word[i];
		label1: switch(c){
		case 'd':
		printf("Get out Hacker");
		return(0);
		break;
		case 'f':
		printf("Get out Hacker");
		return(0);
		break;
		case 'x':
		printf("Get out Hacker");
		return(0);
		break;
		case 'l':
		printf("Get out Hacker");
		return(0);
		break;
		case 's':
		printf("Get out Hacker");
		return(0);
		break;
		case 'c':
		printf("Get out Hacker");
		return(0);
		break;
		default:
		goto label2;
		}
	break;
	//shell shock
	case '(':
		i++;
		c=word[i];
		switch(c){
		case ')':
			i++;
			c=word[i];
			switch(c){
			case '{':
				i++;
				c=word[i];
				switch(c){
				case ':':
					i++;
					c=word[i];
					switch(c){
					case ';':
						i++;
						c=word[i];
						switch(c){
						case '}':
							printf("Get out Hacker");
							return(0);
						break;
						default:
						goto label2;
						}
					break;
					default:
					goto label2;
					}
				break;
				default:
				goto label2;
				}
			break;
			default:
			goto label2;
			}
		break;
		default:
		goto label2;
		}	
	//}
	//dot-dot
	case '.':
		i++;
		c=word[i];
		switch(c){
			case '.':
				i++;
				c=word[i];
				switch(c){
					case '/':
					printf("Get Out Hacker");
					return 0;
					break;
					default:
					goto label2;
				}
			break;
			default:	
			goto label2;
		}
	break;
	case '/':
	i++;
	break;
	//checking '\0'
	case '\0':
	return 1;
	break;
	//OS command injection
	case ';':
	word[i]='\0';
	printf("Get Out Hacker");
	return 1;
	break;
	default:
	i++;
}

}
return 1;
}
