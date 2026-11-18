<?php
declare(strict_types=1);
namespace Shop;

use InvalidArgumentException;
use PDO;

/** Explicit campaign links, never a decision about the requesting visitor. */
final class Channels
{
    public function __construct(private PDO $db)
    {
        $this->db->exec('PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS channel_projects(
                project TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS channel_bindings(
                site TEXT NOT NULL,
                project TEXT NOT NULL REFERENCES channel_projects(project),
                PRIMARY KEY(site,project)
            );
            CREATE TABLE IF NOT EXISTS channel_links(
                site TEXT NOT NULL,
                project TEXT NOT NULL,
                channel TEXT NOT NULL,
                destination TEXT NOT NULL,
                active INTEGER NOT NULL CHECK(active IN (0,1)),
                PRIMARY KEY(site,project,channel),
                FOREIGN KEY(site,project) REFERENCES channel_bindings(site,project) ON DELETE CASCADE
            );');
    }

    public static function slug(string $value): string
    {
        if (!preg_match('/\\A[a-z0-9][a-z0-9-]{0,47}\\z/', $value)) {
            throw new InvalidArgumentException('Invalid site, project or channel identifier');
        }
        return $value;
    }

    public static function destination(string $path): string
    {
        if ($path !== '/' && !preg_match('~\\A/(products|collections)/[a-z0-9][a-z0-9-]{0,79}\\z~', $path)) {
            throw new InvalidArgumentException('Destination must be /, /products/{slug} or /collections/{slug} on this storefront');
        }
        return $path;
    }

    public function bind(string $site, string $project): void
    {
        self::slug($site);
        self::slug($project);
        $this->db->beginTransaction();
        try {
            $this->query('INSERT OR IGNORE INTO channel_projects(project) VALUES(?)', [$project]);
            $this->query('INSERT OR IGNORE INTO channel_bindings(site,project) VALUES(?,?)', [$site, $project]);
            $this->audit('channels.bind', compact('site', 'project'));
            $this->db->commit();
        } catch (\Throwable $error) {
            $this->db->rollBack();
            throw $error;
        }
    }

    public function configure(string $site, string $project, string $channel, string $destination, bool $active): void
    {
        foreach ([$site, $project, $channel] as $slug) {
            self::slug($slug);
        }
        self::destination($destination);
        $this->db->beginTransaction();
        try {
            if (!$this->query('SELECT 1 FROM channel_bindings WHERE site=? AND project=?', [$site, $project])->fetchColumn()) {
                throw new InvalidArgumentException('Bind the project to the site first');
            }
            $this->query('INSERT INTO channel_links VALUES(?,?,?,?,?)
                ON CONFLICT(site,project,channel) DO UPDATE SET destination=excluded.destination, active=excluded.active',
                [$site, $project, $channel, $destination, (int) $active]);
            $this->audit('channels.configure', compact('site', 'project', 'channel', 'destination', 'active'));
            $this->db->commit();
        } catch (\Throwable $error) {
            $this->db->rollBack();
            throw $error;
        }
    }

    public function list(string $site): array
    {
        self::slug($site);
        return $this->query('SELECT b.project, l.channel, l.destination, l.active
            FROM channel_bindings b LEFT JOIN channel_links l ON b.site=l.site AND b.project=l.project
            WHERE b.site=? ORDER BY b.project,l.channel', [$site])->fetchAll(PDO::FETCH_ASSOC);
    }

    public function resolve(string $site, string $project, string $channel): ?string
    {
        foreach ([$site, $project, $channel] as $slug) {
            self::slug($slug);
        }
        $path = $this->query('SELECT destination FROM channel_links WHERE site=? AND project=? AND channel=? AND active=1',
            [$site, $project, $channel])->fetchColumn();
        return $path === false ? null : self::destination($path);
    }

    private function audit(string $action, array $detail): void
    {
        $this->query('INSERT INTO audit(ts,action,detail) VALUES(?,?,?)',
            [time(), $action, json_encode($detail, JSON_THROW_ON_ERROR)]);
    }

    private function query(string $sql, array $args): \PDOStatement
    {
        $query = $this->db->prepare($sql);
        $query->execute($args);
        return $query;
    }
}
