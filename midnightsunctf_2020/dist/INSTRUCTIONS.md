# Starcraft 1 Challenge

En Taro Adun challenger!

Your goal is to exploit an unsuspecting opponent during a game of one of the best games ever: Starcraft.
The goal is to retrieve a file called "flag.pdf" located on their desktop.

The victim will be running a modified version of Starcraft 1.16.1 with a specific patch reverted leaving them vulnerable.
Note that the reverted patch was not introduced in 1.16 but this setup makes the challenge less painful for you to solve.
More background and explanation is provided in the flag.pdf file.

To create a binary equivalent to what the victim is running, start out with version 1.16.1 or Starcraft and apply the patch as shown below:

```
> sha256sum StarCraft.exe
ad6b58b27b8948845ccfa69bcfcc1b10d6aa7a27a371ee3e61453925288c6a46  StarCraft.exe
> bspatch StarCraft.exe Starcraft.patched.exe Starcraft.1.16.1.patch 
> sha256sum StarCraft.patched.exe
350c1ade6ca8ebc079aed06d2ffcaf2d50110010a99236b1aaa3be1e9add0f73  StarCraft.patched.exe
```

To initate the attack you will connect to a custom Battle.net server and create a game that the victim will join.
Use the provided "install_gateway.bat" to add the custom Battle.net server to your server list.
Once you are ready to make an attempt against the victim, connect to the server, create an account and login.
Once logged in you can create a game lobby and set a password.

Then connect to the queue system to submit the name and password of your game lobby.
You also need to submit your CTF team ID and token. You can find them on your profile page: https://ctf.midnightsunctf.se/ -> click "profile" in the menu.

```
> nc bnet.play.midnightsunctf.se 9000
Starcraft pwn challenge queue submission system
Here you can submit a game that you want a bot to join
The current rate limit is: 1 submission/minute
Team id: 1
Team token: TEAM_TOKEN
Starcraft lobby name: my_game
Starcraft lobby password: my_game_password
```

Please only attempt a remote attack once you are confident that you have a working method as the infrastructure for this challenge is fairly resource intensive.
If you have questions about this challenge, contact the author: ZetaTwo, in the chat.

In summary:
1. Get a copy of Starcraft 1.16.1 (The game is free since 2017)
2. Apply provided patch "bspatch StarCraft.exe Starcraft.patched.exe Starcraft.1.16.1.patch"
3. Develop an exploit
4. Add the custom Battle.net server using "install_gateway.bat"
5. Launch the game, connect to the "Midnight Sun CTF" Battle.net server
6. Create an account and login
7. Create a game, and set a password
8. Connect to the queue system and submit the game details: "nc bnet.play.midnightsunctf.se 9000"
9. Wait for the victim to join the lobby
10. Start the game
11. Pwn the victim
12. Retrieve "flag.pdf" from their desktop

Good luck!
