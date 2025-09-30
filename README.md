Dying Light: The Beast - AI Assisted Modding Tool
Welcome to the AI Assisted Modding Tool for Dying Light: The Beast! This powerful tool is designed to make modding accessible to everyone, from beginners to experienced creators. It provides an intuitive interface to help you find, edit, and manage game parameters, allowing you to tweak everything from item prices and weapon stats to player abilities.

This tool was developed with the goal of simplifying the complex process of .pak file modding. Instead of manually unpacking files and searching through thousands of lines of code, you can use our intelligent search and editing features to make precise changes quickly and easily.

Features
Easy .pak File Handling: Simply load the game's main data.pak file, and the tool will handle the extraction process for you in the background.

Intuitive Three-Pane View:

File Explorer: Browse the entire extracted file structure of the game.

File Preview: View the contents of any selected script file, with syntax highlighting for clarity.

Mod Manager: The heart of the tool, where you find and manage all your changes.

Powerful Parameter Search: Enter simple search terms like "pistol ammo price" or "player movespeed" to instantly find the relevant files and lines of code. The tool understands multiple file formats and complex data structures.

Direct-from-Preview Editing: Double-click on any valid parameter directly in the file preview pane to add it to your mod project. The tool intelligently identifies the item you're editing for clear descriptions.

Active Edits Manager: Keep track of all your changes in one clean list. See the original value, your new value, and enable or disable specific edits on the fly.

Project Save/Load: Save your entire mod project to a single .dl3mod file. Share your projects with others or take a break and pick up right where you left off.

One-Click Mod Packing: When you're ready, the tool will take all your enabled edits, apply them to the correct files, and pack them into a game-ready .pak file for you to install.

How to Use
Load Game Data: Click the "Load Game Data (.pak)" button and navigate to your game's main data file (e.g., data0.pak). The tool will extract the files to a temporary directory.

Find a Parameter: In the right-hand pane, type what you want to change into the search bar. For example, to change the price of pistol ammo, you could search for "Ammo_Pistol Price". Press Enter or click "Find Parameters".

Add an Edit: The search results will appear below. Double-click an item in the results list to add it to your "Active Edits". A dialog will pop up asking you to enter the new value.

Manage Your Edits: Your new change will now appear in the "Active Edits" list. You can double-click it to change the value again, uncheck it to temporarily disable it, or right-click to delete it.

Pack Your Mod: Once you are happy with your changes, click the "Pack Mod to .pak File" button. Choose a name and location for your new mod file, and you're done!

Key Features Explained
Intelligent Contextual Editing
When you double-click a value like Price(33) in the file viewer, the tool doesn't just see the number. It intelligently scans upwards to identify the containing block, whether it's an Item("Ammo_Firearm_Pistol", ...) or part of an Assortment("Shop_A", ...) block. It then uses the item's proper name (e.g., "Ammo_Firearm_Pistol") as the description in your edit list, so you always know exactly what you're changing.

Robust Project Management
The Save/Load Project feature is perfect for larger mods. It saves a reference to your source .pak file and a list of every change you've made. This means you can easily update your mod when a new game patch is released. Just load your project, let the tool re-extract the fresh game files, and then repack your mod with all your changes automatically applied to the new files.

Thank you for using the tool, and happy modding!