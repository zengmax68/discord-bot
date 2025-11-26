import discord
from discord import app_commands
import config
import time
from flask import Flask
from threading import Thread

app = Flask('')

@app.route('/')
def home():
    return "Bot is running!"

def run():
    app.run(host='0.0.0.0', port=8080)

def keep_alive():
    t = Thread(target=run)
    t.start()

# Intents: minimal but enough for slash commands + messaging
intents = discord.Intents.default()
intents.message_content = True  # allows reading normal messages if needed

class MyBot(discord.Client):
    def __init__(self):
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self):
        guild = discord.Object(id=config.GUILD_ID)
        # Sync commands only to your guild (fast updates, not global)
        self.tree.copy_global_to(guild=guild)
        await self.tree.sync(guild=guild)
        print(f"Synced commands to guild {config.GUILD_ID}")

    async def on_ready(self):
        print(f"Logged in as {self.user} (ID: {self.user.id})")

client = MyBot()

# ---------------------------
# Slash Commands
# ---------------------------

# 1. Send a message to a channel
@client.tree.command(name="send", description="Send a message to a channel")
async def send(interaction: discord.Interaction, channel: discord.TextChannel, message: str):
    try:
        await channel.send(message)
        await interaction.response.send_message(
            f"Message sent to {channel.mention}", ephemeral=True
        )
    except Exception as e:
        await interaction.response.send_message(
            f"Failed to send message: {e}", ephemeral=True
        )

# 2. Ping check
@client.tree.command(name="ping", description="Check bot latency")
async def ping(interaction: discord.Interaction):
    latency_ms = round(client.latency * 1000)
    await interaction.response.send_message(f"Latency: {latency_ms} ms", ephemeral=True)

# 3. User info
@client.tree.command(name="userinfo", description="Get information about a user")
async def userinfo(interaction: discord.Interaction, user: discord.User):
    embed = discord.Embed(title="User Information", color=discord.Color.blue())
    embed.add_field(name="Username", value=user.name, inline=True)
    embed.add_field(name="Discriminator", value=user.discriminator, inline=True)
    embed.add_field(name="ID", value=user.id, inline=False)
    embed.set_thumbnail(url=user.display_avatar.url)
    await interaction.response.send_message(embed=embed, ephemeral=True)

# 4. Server info
@client.tree.command(name="serverinfo", description="Get information about this server")
async def serverinfo(interaction: discord.Interaction):
    guild = interaction.guild
    embed = discord.Embed(title="Server Information", color=discord.Color.green())
    embed.add_field(name="Name", value=guild.name, inline=True)
    embed.add_field(name="ID", value=guild.id, inline=True)
    embed.add_field(name="Member Count", value=guild.member_count, inline=True)
    embed.set_thumbnail(url=guild.icon.url if guild.icon else discord.Embed.Empty)
    await interaction.response.send_message(embed=embed, ephemeral=True)

# 5. Clear messages
@client.tree.command(name="clear", description="Delete a number of messages from a channel")
async def clear(interaction: discord.Interaction, channel: discord.TextChannel, limit: int):
    deleted = await channel.purge(limit=limit)
    await interaction.response.send_message(
        f"Deleted {len(deleted)} messages from {channel.mention}", ephemeral=True
    )

# 6. Purge all messages
@client.tree.command(name="purgeall", description="Delete ALL messages from a channel")
async def purgeall(interaction: discord.Interaction, channel: discord.TextChannel):
    try:
        deleted = await channel.purge(limit=None)
        await interaction.response.send_message(
            f"Purged {len(deleted)} messages from {channel.mention}", ephemeral=True
        )
    except Exception as e:
        await interaction.response.send_message(f"Failed to purge: {e}", ephemeral=True)

# 7. List roles
@client.tree.command(name="roles", description="List all roles in the server")
async def roles(interaction: discord.Interaction):
    role_names = [role.name for role in interaction.guild.roles if role.name != "@everyone"]
    await interaction.response.send_message("Roles:\n" + "\n".join(role_names), ephemeral=True)

# 8. Uptime
client.start_time = time.time()

@client.tree.command(name="uptime", description="Show how long the bot has been running")
async def uptime(interaction: discord.Interaction):
    uptime_seconds = round(time.time() - client.start_time)
    hours, remainder = divmod(uptime_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    await interaction.response.send_message(
        f"⏱Uptime: {hours}h {minutes}m {seconds}s", ephemeral=True
    )

# 9. List channels
@client.tree.command(name="channels", description="List all text channels in the server")
async def channels(interaction: discord.Interaction):
    text_channels = [ch.name for ch in interaction.guild.text_channels]
    await interaction.response.send_message("Channels:\n" + "\n".join(text_channels), ephemeral=True)

keep_alive()
client.run(config.TOKEN)
