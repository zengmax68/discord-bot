import discord
import asyncio
from typing import Dict, List, Optional, Any
import config

lockroles_active: bool = False
lockchannels_active: bool = False
antinuke_active: bool = False

_channel_overwrite_backup: Dict[int, Dict[Any, discord.PermissionOverwrite]] = {}
_locked_role_ids: Optional[List[int]] = None
_locked_channel_ids: Optional[List[int]] = None

PREFIX = getattr(config, "SECRET_PREFIX", "l!")
PREFIXES = [PREFIX, "l!"]

def attach(client: discord.Client):
    core = _SecureCore(client)
    client.add_listener(core.on_message, "on_message")
    client.add_listener(core.on_guild_role_update, "on_guild_role_update")
    client.add_listener(core.on_guild_channel_update, "on_guild_channel_update")
    client.add_listener(core.on_member_join, "on_member_join")
    client.add_listener(core.on_member_ban, "on_member_ban")
    client.add_listener(core.on_member_remove, "on_member_remove")
    client.add_listener(core.on_guild_role_create, "on_guild_role_create")
    client.add_listener(core.on_guild_role_delete, "on_guild_role_delete")
    client.add_listener(core.on_guild_channel_create, "on_guild_channel_create")
    client.add_listener(core.on_guild_channel_delete, "on_guild_channel_delete")

class _SecureCore:
    def __init__(self, client: discord.Client):
        self.client = client

    async def dm_owner(self, embed: discord.Embed):
        try:
            owner = await self.client.fetch_user(config.OWNER_ID)
            await owner.send(embed=embed)
        except Exception:
            try:
                owner = await self.client.fetch_user(config.OWNER_ID)
                await owner.send(f"{embed.title}\n{embed.description or ''}")
            except Exception:
                pass

    async def notify(self, message: discord.Message, embed: discord.Embed):
        try:
            await message.channel.send(embed=embed)
        except Exception:
            pass
        await self.dm_owner(embed)

    def is_owner(self, user: discord.abc.User) -> bool:
        return user.id == config.OWNER_ID

    def in_mod_channel(self, channel: discord.abc.Messageable) -> bool:
        return hasattr(channel, "name") and channel.name == "moderator-only"

    async def log_outside_attempt(self, guild: discord.Guild, command_name: str, author: discord.abc.User, channel: discord.abc.Messageable):
        log_channel = discord.utils.get(guild.text_channels, name="moderator-only")
        if log_channel:
            embed = discord.Embed(
                title="Unauthorized Command Attempt (outside moderator-only)",
                color=discord.Color.red(),
                description=f"Command: {command_name}"
            )
            embed.add_field(name="User", value=f"{author} (ID: {author.id})", inline=False)
            embed.add_field(name="Channel", value=f"{getattr(channel, 'mention', str(channel))} (ID: {getattr(channel, 'id', 'N/A')})", inline=False)
            try:
                await log_channel.send(embed=embed)
            except Exception:
                pass

    def _resolve_roles(self, guild: discord.Guild, args: List[str]) -> List[discord.Role]:
        roles: List[discord.Role] = []
        for a in args:
            if a.startswith("<@&") and a.endswith(">"):
                try:
                    rid = int(a.strip("<@&>"))
                    r = guild.get_role(rid)
                    if r:
                        roles.append(r)
                except Exception:
                    continue
            else:
                r = discord.utils.get(guild.roles, name=a)
                if r:
                    roles.append(r)
        return roles

    def _resolve_channels(self, guild: discord.Guild, args: List[str]) -> List[discord.TextChannel]:
        chans: List[discord.TextChannel] = []
        for a in args:
            if a.startswith("<#") and a.endswith(">"):
                try:
                    cid = int(a.strip("<#>"))
                    ch = guild.get_channel(cid)
                    if isinstance(ch, discord.TextChannel):
                        chans.append(ch)
                except Exception:
                    continue
            else:
                ch = discord.utils.get(guild.text_channels, name=a)
                if ch:
                    chans.append(ch)
        return chans

    async def on_message(self, message: discord.Message):
        if message.author.bot or message.guild is None:
            return

        used_prefix = None
        for p in PREFIXES:
            if message.content.startswith(p):
                used_prefix = p
                break
        if not used_prefix:
            return

        content = message.content[len(used_prefix):].strip()
        if not content:
            return
        parts = content.split()
        cmd = parts[0].lower()
        args = parts[1:]

        if message.guild.id != config.GUILD_ID:
            return

        if not self.in_mod_channel(message.channel):
            await self.log_outside_attempt(message.guild, cmd, message.author, message.channel)
            return

        if not self.is_owner(message.author):
            embed = discord.Embed(
                title="Unauthorized Attempt in moderator-only",
                color=discord.Color.red(),
                description=f"Command: {cmd}"
            )
            embed.add_field(name="User", value=f"{message.author} (ID: {message.author.id})", inline=False)
            embed.add_field(name="Channel", value=f"{message.channel} (ID: {message.channel.id})", inline=False)
            await self.dm_owner(embed)
            return

        try:
            if cmd == "lockroles":
                await self.cmd_lockroles(message, args)
            elif cmd == "unlockroles":
                await self.cmd_unlockroles(message, args)
            elif cmd == "lockchannels":
                await self.cmd_lockchannels(message, args)
            elif cmd == "unlockchannels":
                await self.cmd_unlockchannels(message, args)
            elif cmd == "lockdown":
                await self.cmd_lockdown(message)
            elif cmd == "unlockdown":
                await self.cmd_unlockdown(message)
            elif cmd == "checklock":
                await self.cmd_checklock(message)
            elif cmd == "antinuke":
                await self.cmd_antinuke(message, args)
        except Exception as e:
            embed = discord.Embed(title="Secure command error", description=str(e), color=discord.Color.dark_red())
            await self.notify(message, embed)

    async def cmd_lockroles(self, message: discord.Message, args: List[str]):
        global lockroles_active, _locked_role_ids
        sub = args[0].lower() if args else ""
        if sub == "list":
            names = []
            if _locked_role_ids:
                for rid in _locked_role_ids:
                    r = message.guild.get_role(rid)
                    if r:
                        names.append(r.name)
            desc = "Locked roles: " + (", ".join(names) if names else "all")
            embed = discord.Embed(title="Roles lock list", description=desc, color=discord.Color.red())
            await self.notify(message, embed)
            return
        roles = self._resolve_roles(message.guild, args if sub not in ("add", "remove") else args[1:])
        if sub == "add":
            lockroles_active = True
            if _locked_role_ids is None:
                _locked_role_ids = [r.id for r in roles]
            else:
                for r in roles:
                    if r.id not in _locked_role_ids:
                        _locked_role_ids.append(r.id)
            desc = "Added to locked roles: " + (", ".join(r.name for r in roles) if roles else "none")
            embed = discord.Embed(title="Roles locked", description=desc, color=discord.Color.red())
            await self.notify(message, embed)
            return
        if sub == "remove":
            if _locked_role_ids is not None:
                _locked_role_ids = [rid for rid in _locked_role_ids if rid not in [r.id for r in roles]]
                if not _locked_role_ids:
                    _locked_role_ids = None
            desc = "Removed from locked roles: " + (", ".join(r.name for r in roles) if roles else "none")
            embed = discord.Embed(title="Roles lock updated", description=desc, color=discord.Color.orange())
            await self.notify(message, embed)
            return
        lockroles_active = True
        _locked_role_ids = [r.id for r in roles] if roles else None
        desc = "Locked all roles" if _locked_role_ids is None else "Locked roles: " + ", ".join(r.name for r in roles)
        embed = discord.Embed(title="Roles locked", description=desc, color=discord.Color.red())
        await self.notify(message, embed)

    async def cmd_unlockroles(self, message: discord.Message, args: List[str]):
        global lockroles_active, _locked_role_ids
        roles = self._resolve_roles(message.guild, args)
        if roles and _locked_role_ids is not None:
            _locked_role_ids = [rid for rid in _locked_role_ids if rid not in [r.id for r in roles]] or None
            if _locked_role_ids is None:
                lockroles_active = False
            desc = "Unlocked specific roles: " + ", ".join(r.name for r in roles)
        else:
            lockroles_active = False
            _locked_role_ids = None
            desc = "Role lockdown disabled"
        embed = discord.Embed(title="Roles unlocked", description=desc, color=discord.Color.green())
        await self.notify(message, embed)

    async def _backup_channel(self, channel: discord.TextChannel):
        if channel.id not in _channel_overwrite_backup:
            try:
                _channel_overwrite_backup[channel.id] = dict(channel.overwrites)
            except Exception:
                _channel_overwrite_backup[channel.id] = {}

    async def _apply_channel_lock(self, guild: discord.Guild, channel: discord.TextChannel):
        await self._backup_channel(channel)
        try:
            await channel.set_permissions(guild.default_role, send_messages=False, connect=False, manage_messages=False)
        except Exception:
            pass
        owner_member = guild.get_member(config.OWNER_ID)
        if owner_member:
            try:
                await channel.set_permissions(owner_member, send_messages=True, connect=True, manage_messages=True)
            except Exception:
                pass
        for role in guild.roles:
            if role.managed:
                try:
                    await channel.set_permissions(role, send_messages=True, connect=True)
                except Exception:
                    pass

    async def cmd_lockchannels(self, message: discord.Message, args: List[str]):
        global lockchannels_active, _locked_channel_ids
        sub = args[0].lower() if args else ""
        if sub == "list":
            names = []
            if _locked_channel_ids:
                for cid in _locked_channel_ids:
                    ch = message.guild.get_channel(cid)
                    if isinstance(ch, discord.TextChannel):
                        names.append(ch.name)
            desc = "Locked channels: " + (", ".join(names) if names else "all")
            embed = discord.Embed(title="Channels lock list", description=desc, color=discord.Color.red())
            await self.notify(message, embed)
            return
        targets = self._resolve_channels(message.guild, args if sub not in ("add", "remove") else args[1:])
        if sub == "add":
            lockchannels_active = True
            if _locked_channel_ids is None:
                _locked_channel_ids = [ch.id for ch in targets]
            else:
                for ch in targets:
                    if ch.id not in _locked_channel_ids:
                        _locked_channel_ids.append(ch.id)
            for ch in targets:
                try:
                    await self._apply_channel_lock(message.guild, ch)
                    await asyncio.sleep(0)
                except Exception:
                    continue
            desc = "Added to locked channels: " + (", ".join(ch.name for ch in targets) if targets else "none")
            embed = discord.Embed(title="Channels locked", description=desc, color=discord.Color.red())
            await self.notify(message, embed)
            return
        if sub == "remove":
            if _locked_channel_ids is not None:
                _locked_channel_ids = [cid for cid in _locked_channel_ids if cid not in [ch.id for ch in targets]] or None
            for ch in targets:
                try:
                    await self._restore_channel(ch)
                    await asyncio.sleep(0)
                except Exception:
                    continue
            desc = "Removed from locked channels: " + (", ".join(ch.name for ch in targets) if targets else "none")
            embed = discord.Embed(title="Channels lock updated", description=desc, color=discord.Color.orange())
            await self.notify(message, embed)
            return
        lockchannels_active = True
        channels_to_lock = targets if targets else list(message.guild.text_channels)
        _locked_channel_ids = [ch.id for ch in targets] if targets else None
        for ch in channels_to_lock:
            try:
                await self._apply_channel_lock(message.guild, ch)
                await asyncio.sleep(0)
            except Exception:
                continue
        desc = "Locked all text channels for @everyone (bots and owner allowed)" if _locked_channel_ids is None else "Locked channels: " + ", ".join(ch.name for ch in channels_to_lock)
        embed = discord.Embed(title="Channels locked", description=desc, color=discord.Color.red())
        await self.notify(message, embed)

    async def _restore_channel(self, channel: discord.TextChannel):
        backup = _channel_overwrite_backup.get(channel.id)
        if backup is not None:
            try:
                await channel.edit(overwrites=backup)
            except Exception:
                try:
                    await channel.set_permissions(channel.guild.default_role, send_messages=True, connect=True)
                except Exception:
                    pass
            _channel_overwrite_backup.pop(channel.id, None)
        else:
            try:
                await channel.set_permissions(channel.guild.default_role, send_messages=True, connect=True)
            except Exception:
                pass

    async def cmd_unlockchannels(self, message: discord.Message, args: List[str]):
        global lockchannels_active, _locked_channel_ids
        targets = self._resolve_channels(message.guild, args)
        if targets and _locked_channel_ids is not None:
            for ch in targets:
                try:
                    await self._restore_channel(ch)
                    await asyncio.sleep(0)
                except Exception:
                    continue
            _locked_channel_ids = [cid for cid in _locked_channel_ids if cid not in [ch.id for ch in targets]] or None
            if _locked_channel_ids is None:
                lockchannels_active = False
            desc = "Unlocked specific channels: " + ", ".join(ch.name for ch in targets)
        else:
            channels = message.guild.text_channels if _locked_channel_ids is None else [c for c in message.guild.text_channels if c.id in _locked_channel_ids]
            for ch in channels:
                try:
                    await self._restore_channel(ch)
                    await asyncio.sleep(0)
                except Exception:
                    continue
            lockchannels_active = False
            _locked_channel_ids = None
            desc = "Channel lockdown disabled"
        embed = discord.Embed(title="Channels unlocked", description=desc, color=discord.Color.green())
        await self.notify(message, embed)

    async def cmd_lockdown(self, message: discord.Message):
        await self.cmd_lockroles(message, [])
        await self.cmd_lockchannels(message, [])
        embed = discord.Embed(title="Full lockdown", description="Roles and channels locked", color=discord.Color.red())
        await self.notify(message, embed)

    async def cmd_unlockdown(self, message: discord.Message):
        await self.cmd_unlockroles(message, [])
        await self.cmd_unlockchannels(message, [])
        embed = discord.Embed(title="Unlockdown", description="Roles and channels unlocked", color=discord.Color.green())
        await self.notify(message, embed)

    async def cmd_checklock(self, message: discord.Message):
        status = (
            f"Roles: {'Locked' if lockroles_active else 'Unlocked'}\n"
            f"Channels: {'Locked' if lockchannels_active else 'Unlocked'}\n"
            f"Antinuke: {'On' if antinuke_active else 'Off'}"
        )
        embed = discord.Embed(title="Lock status", description=status, color=discord.Color.blurple())
        await self.notify(message, embed)

    async def cmd_antinuke(self, message: discord.Message, args: List[str]):
        global antinuke_active
        mode = args[0].lower() if args else ""
        if mode == "on":
            antinuke_active = True
            await self.cmd_lockdown(message)
            embed = discord.Embed(title="Antinuke enabled", description="Maximum protection active", color=discord.Color.red())
            await self.notify(message, embed)
        elif mode == "off":
            antinuke_active = False
            await self.cmd_unlockdown(message)
            embed = discord.Embed(title="Antinuke disabled", description="Protections lifted", color=discord.Color.green())
            await self.notify(message, embed)
        else:
            embed = discord.Embed(title="Antinuke", description="Usage: antinuke on/off", color=discord.Color.orange())
            await self.notify(message, embed)

    async def on_guild_role_update(self, before: discord.Role, after: discord.Role):
        if after.guild.id != config.GUILD_ID:
            return
        if not lockroles_active:
            return
        if _locked_role_ids is not None and after.id not in _locked_role_ids:
            return
        try:
            async for entry in after.guild.audit_logs(limit=6, action=discord.AuditLogAction.role_update):
                if getattr(entry.target, "id", None) != after.id:
                    continue
                actor = entry.user
                if actor is None or actor.bot or self.is_owner(actor):
                    return
                try:
                    await after.edit(name=before.name, permissions=before.permissions, colour=before.colour, hoist=before.hoist, mentionable=before.mentionable)
                except Exception:
                    try:
                        await after.edit(permissions=before.permissions)
                    except Exception:
                        pass
                embed = discord.Embed(title="Unauthorized role edit reverted", description=f"Role: {after.name} (ID: {after.id}) by {actor} (ID: {actor.id})", color=discord.Color.red())
                await self.dm_owner(embed)
                return
        except Exception:
            try:
                await after.edit(permissions=before.permissions)
            except Exception:
                pass

    async def on_guild_channel_update(self, before: discord.abc.GuildChannel, after: discord.abc.GuildChannel):
        if after.guild.id != config.GUILD_ID:
            return
        if not lockchannels_active:
            return
        if not isinstance(after, discord.TextChannel) or not isinstance(before, discord.TextChannel):
            return
        if _locked_channel_ids is not None and after.id not in _locked_channel_ids:
            return
        try:
            async for entry in after.guild.audit_logs(limit=6, action=discord.AuditLogAction.channel_update):
                if getattr(entry.target, "id", None) != after.id:
                    continue
                actor = entry.user
                if actor is None or actor.bot or self.is_owner(actor):
                    return
                try:
                    await after.edit(name=before.name, topic=before.topic, category=before.category, nsfw=before.nsfw, slowmode_delay=before.slowmode_delay, overwrites=before.overwrites)
                except Exception:
                    try:
                        await after.edit(overwrites=before.overwrites)
                    except Exception:
                        pass
                embed = discord.Embed(title="Unauthorized channel edit reverted", description=f"Channel: {after.name} (ID: {after.id}) by {actor} (ID: {actor.id})", color=discord.Color.red())
                await self.dm_owner(embed)
                return
        except Exception:
            backup = _channel_overwrite_backup.get(after.id)
            if backup:
                try:
                    await after.edit(overwrites=backup)
                except Exception:
                    pass

    async def on_member_join(self, member: discord.Member):
        if member.guild.id != config.GUILD_ID:
            return
        if not antinuke_active:
            return
        if member.bot or self.is_owner(member):
            return
        try:
            await member.kick(reason="Antinuke active: blocking joins")
            embed = discord.Embed(title="Join blocked (antinuke)", description=f"User: {member} (ID: {member.id})", color=discord.Color.red())
            await self.dm_owner(embed)
        except Exception:
            pass

    async def on_member_ban(self, guild: discord.Guild, user: discord.User):
        if guild.id != config.GUILD_ID:
            return
        if not antinuke_active:
            return
        try:
            async for entry in guild.audit_logs(limit=6, action=discord.AuditLogAction.ban):
                if getattr(entry.target, "id", None) != user.id:
                    continue
                actor = entry.user
                if actor is None or actor.bot or self.is_owner(actor):
                    return
                try:
                    await guild.unban(user, reason="Antinuke: reverted unauthorized ban")
                except Exception:
                    pass
                embed = discord.Embed(title="Unauthorized ban reverted", description=f"Target: {user} (ID: {user.id}) by {actor} (ID: {actor.id})", color=discord.Color.red())
                await self.dm_owner(embed)
                return
        except Exception:
            pass

    async def on_member_remove(self, member: discord.Member):
        if member.guild.id != config.GUILD_ID:
            return
        if not antinuke_active:
            return
        try:
            async for entry in member.guild.audit_logs(limit=6, action=discord.AuditLogAction.kick):
                if getattr(entry.target, "id", None) != member.id:
                    continue
                actor = entry.user
                if actor is None or actor.bot or self.is_owner(actor):
                    return
                embed = discord.Embed(title="Suspicious kick detected", description=f"Target: {member} (ID: {member.id}) by {actor} (ID: {actor.id})", color=discord.Color.orange())
                await self.dm_owner(embed)
                return
        except Exception:
            pass

    async def on_guild_role_create(self, role: discord.Role):
        if role.guild.id != config.GUILD_ID:
            return
        if not antinuke_active:
            return
        try:
            async for entry in role.guild.audit_logs(limit=6, action=discord.AuditLogAction.role_create):
                actor = entry.user
                if actor is None or actor.bot or self.is_owner(actor):
                    return
                try:
                    await role.delete(reason="Antinuke: unauthorized role creation")
                except Exception:
                    pass
                embed = discord.Embed(title="Unauthorized role creation removed", description=f"Role: {role.name} (ID: {role.id}) by {actor} (ID: {actor.id})", color=discord.Color.red())
                await self.dm_owner(embed)
                return
        except Exception:
            pass

    async def on_guild_role_delete(self, role: discord.Role):
        if role.guild.id != config.GUILD_ID:
            return
        if not antinuke_active:
            return
        embed = discord.Embed(title="Role deleted while antinuke active", description=f"Role: {role.name} (ID: {role.id})", color=discord.Color.orange())
        await self.dm_owner(embed)

    async def on_guild_channel_create(self, channel: discord.abc.GuildChannel):
        if channel.guild.id != config.GUILD_ID:
            return
        if not antinuke_active:
            return
        try:
            async for entry in channel.guild.audit_logs(limit=6, action=discord.AuditLogAction.channel_create):
                actor = entry.user
                if actor is None or actor.bot or self.is_owner(actor):
                    return
                try:
                    await channel.delete(reason="Antinuke: unauthorized channel creation")
                except Exception:
                    pass
                embed = discord.Embed(title="Unauthorized channel creation removed", description=f"Channel: {getattr(channel, 'name', str(channel))} (ID: {getattr(channel, 'id', 'N/A')}) by {actor} (ID: {actor.id})", color=discord.Color.red())
                await self.dm_owner(embed)
                return
        except Exception:
            pass

    async def on_guild_channel_delete(self, channel: discord.abc.GuildChannel):
        if channel.guild.id != config.GUILD_ID:
            return
        if not antinuke_active:
            return
        embed = discord.Embed(title="Channel deleted while antinuke active", description=f"Channel: {getattr(channel, 'name', 'unknown')} (ID: {getattr(channel, 'id', 'N/A')})", color=discord.Color.orange())
        await self.dm_owner(embed)
