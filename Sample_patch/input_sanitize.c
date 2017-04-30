/* reference checking file permissions - https://unix.stackexchange.com/questions/82347/how-to-check-if-a-user-can-access-a-given-file
http://www.sanfoundry.com/chroot-command-usage-examples-linux/
*/
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

/* Reference - http://coding.debuntu.org/c-implementing-str_replace-replace-all-occurrences-substring */
char *  replace_str (  char *string,  char *substr,  char *replacement ){
	char *tok = NULL;
	char *newstr = NULL;
	char *oldstr = NULL;
	char *head = NULL;
	if ( substr == NULL || replacement == NULL ) return strdup (string);
		newstr = strdup (string);
		head = newstr;
		while ( (tok = strstr ( head, substr ))){
			oldstr = newstr;
			newstr = malloc ( strlen ( oldstr ) - strlen ( substr ) + strlen ( replacement ) + 1 );
			if ( newstr == NULL ){
			  free (oldstr);
			  return NULL;
			}
		memcpy ( newstr, oldstr, tok - oldstr );
		memcpy ( newstr + (tok - oldstr), replacement, strlen ( replacement ) );
		memcpy ( newstr + (tok - oldstr) + strlen( replacement ), tok + strlen ( substr ), strlen ( oldstr ) - strlen ( substr ) - ( tok - oldstr ) );
		memset ( newstr + strlen ( oldstr ) - strlen ( substr ) + strlen ( replacement ) , 0, 1 );
		head = newstr + (tok - oldstr) + strlen( replacement );		
	}
	
	return newstr;
}

char* sanitize(char *word) //1-success
{
//checking character by character
int i=0;
loopstart: i=0;
char c;
char chrootcmd[50]="";
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
		word = replace_str(word,"%d","");
		goto loopstart;
		break;
		case 'n':
		word = replace_str(word,"%n","");
		goto loopstart;
		break;		
		case 'f':
		word = replace_str(word,"%f","");
		goto loopstart;
		break;
		case 'x':
		word = replace_str(word,"%x","");
		goto loopstart;
		break;
		case 'l':
		word = replace_str(word,"%l","");
		goto loopstart;
		break;
		case 's':
		word = replace_str(word,"%s","");
		goto loopstart;
		break;
		case 'c':
		word = replace_str(word,"%c","");
		goto loopstart;
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
							word = replace_str(word,"(){:;}","");
							goto loopstart;							
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
					word = replace_str(word,"../","");
					goto loopstart;
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
	break;
	//OS command injection
	case ';':
	word[i]='\0';
	word = replace_str(word,";","");
	goto loopstart;
	break;
	default:
	i++;
}

}
return word;
}
	

int main (int argc, char **argv)
{
char str[256];
printf(" Enter input ");
gets(str);
printf(" %s ",sanitize(str));
return 0;
}
