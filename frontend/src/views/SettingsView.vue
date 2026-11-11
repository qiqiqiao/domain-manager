<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h1 class="page-title">系统设置</h1>
        <p class="page-subtitle">调整告警阈值、任务频率、安全策略与 ACME 默认配置。</p>
      </div>
      <div class="page-actions">
        <el-tag type="info" effect="plain" size="large">v{{ system?.version || '1.0.0' }}</el-tag>
      </div>
    </div>

    <div class="panel settings-panel">
      <el-tabs v-model="activeTab" class="settings-tabs">
        <el-tab-pane label="基础配置" name="general">
          <div class="settings-body">
            <section class="settings-section">
              <div class="section-heading">
                <h3>站点信息</h3>
                <p>用于管理后台展示与 ACME 申请中的默认信息。</p>
              </div>
              <div class="form-grid">
                <el-form-item label="站点名称">
                  <el-input v-model="form.site_name" placeholder="Domain Manager" />
                </el-form-item>
                <el-form-item label="站点 URL">
                  <el-input v-model="form.site_url" placeholder="https://dm.example.com" />
                </el-form-item>
                <el-form-item label="时区">
                  <el-select v-model="form.timezone" filterable allow-create default-first-option style="width: 100%">
                    <el-option v-for="tz in timezones" :key="tz" :label="tz" :value="tz" />
                  </el-select>
                </el-form-item>
                <el-form-item label="公开访问 URL（可选）">
                  <el-input v-model="form.public_url" placeholder="用于外部部署脚本或文档" />
                </el-form-item>
              </div>
            </section>

            <section class="settings-section">
              <div class="section-heading">
                <h3>到期告警阈值</h3>
                <p>以逗号分隔天数，按从大到小触发。域名可配置 0 表示到期当天；证书到期当天会自动告警。</p>
              </div>
              <div class="form-grid">
                <el-form-item label="域名提前预警天数">
                  <el-input-number v-model="form.domain_warning_days" :min="1" :max="365" controls-position="right" style="width: 100%" />
                </el-form-item>
                <el-form-item label="证书提前预警天数">
                  <el-input-number v-model="form.ssl_warning_days" :min="1" :max="365" controls-position="right" style="width: 100%" />
                </el-form-item>
                <el-form-item label="域名告警阈值（天）">
                  <el-input v-model="form.domain_thresholds_text" placeholder="30, 15, 7, 3, 1, 0" />
                  <div class="form-hint">默认：30 / 15 / 7 / 3 / 1 / 0 天</div>
                </el-form-item>
                <el-form-item label="SSL 证书告警阈值（天）">
                  <el-input v-model="form.ssl_thresholds_text" placeholder="30, 15, 7, 3, 1" />
                  <div class="form-hint">默认：30 / 15 / 7 / 3 / 1 天</div>
                </el-form-item>
              </div>
            </section>

            <section class="settings-section">
              <div class="section-heading">
                <h3>检测与安全策略</h3>
                <p>控制外部查询超时、并发数以及 SSRF 防护策略。</p>
              </div>
              <div class="form-grid">
                <el-form-item label="HTTP/HTTPS 检测超时（秒）">
                  <el-input-number v-model="form.http_timeout_seconds" :min="3" :max="120" controls-position="right" style="width: 100%" />
                </el-form-item>
                <el-form-item label="RDAP 查询超时（秒）">
                  <el-input-number v-model="form.rdap_timeout_seconds" :min="3" :max="120" controls-position="right" style="width: 100%" />
                </el-form-item>
                <el-form-item label="最大并发检测数">
                  <el-input-number v-model="form.max_concurrency" :min="1" :max="50" controls-position="right" style="width: 100%" />
                </el-form-item>
                <el-form-item label="通知失败最大重试次数">
                  <el-input-number v-model="form.notification_max_retries" :min="1" :max="20" controls-position="right" style="width: 100%" />
                </el-form-item>
              </div>
              <div class="switch-list">
                <div class="switch-item">
                  <div><strong>启用 WHOIS 兜底查询</strong><span>RDAP 无法提供完整信息时，通过 TCP 43 端口查询 WHOIS。</span></div>
                  <el-switch v-model="form.whois_enabled" />
                </div>
                <div class="switch-item">
                  <div><strong class="danger-text">允许监控内网地址</strong><span>默认关闭以防止 SSRF。开启后可能允许探测内网服务，生产环境请谨慎。</span></div>
                  <el-switch v-model="form.allow_private_targets" />
                </div>
              </div>
              <el-alert
                v-if="form.allow_private_targets"
                class="section-alert"
                type="warning"
                :closable="false"
                show-icon
                title="已允许访问内网地址。请确保系统仅由可信管理员访问，并了解 SSRF 风险。"
              />
            </section>

            <div class="save-bar">
              <el-button type="primary" :loading="saving" @click="saveAll">保存基础配置</el-button>
            </div>
          </div>
        </el-tab-pane>

        <el-tab-pane label="定时任务" name="scheduler">
          <div class="settings-body">
            <section class="settings-section">
              <div class="section-heading">
                <h3>任务执行频率</h3>
                <p>使用标准 5 段 Cron 表达式（分 时 日 月 周），保存后调度器立即重新加载。</p>
              </div>
              <div class="form-grid">
                <el-form-item label="域名到期检查">
                  <el-input v-model="form.domain_check_cron" class="cron-input" />
                  <div class="form-hint">默认每天 03:00：0 3 * * *</div>
                </el-form-item>
                <el-form-item label="SSL 证书检查">
                  <el-input v-model="form.ssl_check_cron" class="cron-input" />
                  <div class="form-hint">默认每 6 小时：0 */6 * * *</div>
                </el-form-item>
                <el-form-item label="证书续期检查">
                  <el-input v-model="form.renewal_check_cron" class="cron-input" />
                  <div class="form-hint">默认每天 04:00：0 4 * * *</div>
                </el-form-item>
                <el-form-item label="告警扫描">
                  <el-input v-model="form.alert_scan_cron" class="cron-input" />
                  <div class="form-hint">默认每小时：0 * * * *</div>
                </el-form-item>
                <el-form-item label="通知失败重试">
                  <el-input v-model="form.notification_retry_cron" class="cron-input" />
                  <div class="form-hint">默认每 10 分钟：*/10 * * * *</div>
                </el-form-item>
                <el-form-item label="日志保留天数">
                  <el-input-number v-model="form.log_retention_days" :min="1" :max="3650" controls-position="right" style="width: 100%" />
                  <div class="form-hint">每日 03:30 清理更早的监控日志、通知日志与任务记录</div>
                </el-form-item>
              </div>
              <div class="save-bar inner">
                <el-button type="primary" :loading="saving" @click="saveAll">保存任务频率</el-button>
              </div>
            </section>

            <section class="settings-section">
              <div class="section-heading row-heading">
                <div>
                  <h3>任务运行状态</h3>
                  <p>查看上次执行结果，或手动触发任务。</p>
                </div>
                <el-button size="small" :icon="Refresh" @click="loadJobs">刷新</el-button>
              </div>
              <el-table :data="jobs" class="dm-table" size="small">
                <el-table-column label="任务" min-width="150">
                  <template #default="{ row }">
                    <div class="job-name"><strong>{{ row.name }}</strong><span class="mono">{{ row.cron }}</span></div>
                  </template>
                </el-table-column>
                <el-table-column label="最近运行" width="165">
                  <template #default="{ row }">{{ formatDateTime(row.last_run_at) }}</template>
                </el-table-column>
                <el-table-column label="结果" width="100">
                  <template #default="{ row }">
                    <el-tag v-if="row.last_status" size="small" :type="row.last_status === 'success' ? 'success' : 'danger'" effect="plain">
                      {{ row.last_status === 'success' ? '成功' : '失败' }}
                    </el-tag>
                    <span v-else class="muted">尚未运行</span>
                  </template>
                </el-table-column>
                <el-table-column label="耗时" width="90">
                  <template #default="{ row }">{{ formatDuration(row.last_duration_ms) }}</template>
                </el-table-column>
                <el-table-column label="下次运行" width="165">
                  <template #default="{ row }">{{ formatDateTime(row.next_run_at) }}</template>
                </el-table-column>
                <el-table-column label="操作" width="90">
                  <template #default="{ row }">
                    <el-button link type="primary" :loading="runningJob === row.key" @click="runJob(row)">立即执行</el-button>
                  </template>
                </el-table-column>
              </el-table>
              <div v-if="recentRuns.length" class="run-history">
                <h4>最近执行记录</h4>
                <div v-for="run in recentRuns" :key="run.id" class="run-row">
                  <el-tag size="small" :type="run.status === 'success' ? 'success' : 'danger'" effect="plain">{{ run.status }}</el-tag>
                  <span class="mono">{{ run.job_key }}</span>
                  <span>{{ run.message }}</span>
                  <span class="muted">{{ formatDateTime(run.started_at) }}</span>
                </div>
              </div>
            </section>
          </div>
        </el-tab-pane>

        <el-tab-pane label="安全设置" name="security">
          <div class="settings-body">
            <section class="settings-section">
              <div class="section-heading">
                <h3>修改管理员密码</h3>
                <p>修改后所有会话将失效，需要使用新密码重新登录。</p>
              </div>
              <el-form ref="passwordFormRef" :model="passwordForm" :rules="passwordRules" label-position="top" class="password-form">
                <el-form-item label="当前密码" prop="current">
                  <el-input v-model="passwordForm.current" type="password" show-password autocomplete="current-password" />
                </el-form-item>
                <el-form-item label="新密码" prop="next">
                  <el-input v-model="passwordForm.next" type="password" show-password autocomplete="new-password" />
                  <div class="form-hint">至少 8 个字符，建议使用大小写字母、数字和符号组合。</div>
                </el-form-item>
                <el-form-item label="确认新密码" prop="confirm">
                  <el-input v-model="passwordForm.confirm" type="password" show-password autocomplete="new-password" />
                </el-form-item>
                <el-button type="primary" :loading="changingPassword" @click="submitPassword">修改密码并重新登录</el-button>
              </el-form>
            </section>

            <section v-if="!auth.user?.must_change_password" class="settings-section">
              <div class="section-heading">
                <h3>二次认证（TOTP）</h3>
                <p>启用后，登录时除密码外还需要身份验证器生成的动态验证码。密钥经加密后保存在本地数据库。</p>
              </div>
              <div class="totp-status">
                <div class="totp-status-text">
                  <el-tag :type="totpEnabled ? 'success' : 'info'" effect="plain">{{ totpEnabled ? '已启用' : '未启用' }}</el-tag>
                  <span>支持 Google Authenticator、Microsoft Authenticator、1Password 等 TOTP 应用。</span>
                </div>
                <div class="totp-actions">
                  <el-button v-if="!totpEnabled" type="primary" @click="openTOTPDialog('enable')">启用二次认证</el-button>
                  <template v-else>
                    <el-button @click="openTOTPDialog('regen')">重新生成恢复码</el-button>
                    <el-button type="danger" plain @click="openTOTPDialog('disable')">关闭二次认证</el-button>
                  </template>
                </div>
              </div>
              <div class="alert-box">
                如果丢失身份验证器，请使用启用时保存的一次性恢复码登录。恢复码只显示一次，请妥善保管。
              </div>
            </section>

            <section class="settings-section">
              <div class="section-heading">
                <h3>登录与会话策略</h3>
                <p>登录失败限制按“用户名 + 来源 IP”计数，不会因单一 IP 的失败而全局锁定账号。</p>
              </div>
              <div class="form-grid">
                <el-form-item label="会话有效期（小时）">
                  <el-input-number v-model="form.session_ttl_hours" :min="1" :max="720" controls-position="right" style="width: 100%" />
                </el-form-item>
                <el-form-item label="最大登录失败次数">
                  <el-input-number v-model="form.login_max_attempts" :min="1" :max="20" controls-position="right" style="width: 100%" />
                </el-form-item>
                <el-form-item label="账号锁定时长（分钟）">
                  <el-input-number v-model="form.login_lock_minutes" :min="1" :max="1440" controls-position="right" style="width: 100%" />
                </el-form-item>
              </div>
              <div class="alert-box">
                初始管理员密码写入 data/initial-admin-password（0600），不再输出到日志。首次登录未修改密码前，除认证接口外的 API 均返回 403。
              </div>
              <div class="save-bar inner">
                <el-button type="primary" :loading="saving" @click="saveAll">保存安全设置</el-button>
              </div>
            </section>
          </div>
        </el-tab-pane>

        <el-tab-pane label="ACME 与部署" name="acme">
          <div class="settings-body">
            <section class="settings-section">
              <div class="section-heading">
                <h3>Let's Encrypt 默认配置</h3>
                <p>证书申请页面会载入这些默认值，仍可为单次订单单独选择环境。</p>
              </div>
              <div class="form-grid">
                <el-form-item label="ACME 账号邮箱">
                  <el-input v-model="form.acme_email" placeholder="admin@example.com" />
                </el-form-item>
                <el-form-item label="默认证书密钥类型">
                  <el-select v-model="form.acme_key_type" style="width: 100%">
                    <el-option label="RSA 2048" value="rsa2048" />
                    <el-option label="RSA 4096" value="rsa4096" />
                    <el-option label="ECDSA P-256" value="ec256" />
                    <el-option label="ECDSA P-384" value="ec384" />
                  </el-select>
                </el-form-item>
                <el-form-item label="自动续期提前天数">
                  <el-input-number v-model="form.acme_renew_days" :min="1" :max="90" controls-position="right" style="width: 100%" />
                </el-form-item>
                <el-form-item label="订单最大自动重试次数">
                  <el-input-number v-model="form.acme_max_attempts" :min="1" :max="10" controls-position="right" style="width: 100%" />
                </el-form-item>
                <el-form-item label="订单处理并发数">
                  <el-input-number v-model="form.acme_concurrency" :min="1" :max="10" controls-position="right" style="width: 100%" />
                  <div class="form-hint">修改后需重启服务生效；并发过高可能触发 CA 限流</div>
                </el-form-item>
                <el-form-item label="重试耗尽后的冷却（小时）">
                  <el-input-number v-model="form.acme_renew_cooldown_hours" :min="1" :max="720" controls-position="right" style="width: 100%" />
                  <div class="form-hint">重试次数耗尽后，冷却结束会重新创建自动续期订单</div>
                </el-form-item>
                <el-form-item label="默认 DNS Provider">
                  <el-select v-model="form.acme_default_dns_provider" style="width: 100%">
                    <el-option label="Cloudflare" value="cloudflare" />
                    <el-option label="DNSPod / 腾讯云" value="dnspod" />
                    <el-option label="阿里云 DNS" value="alidns" />
                  </el-select>
                </el-form-item>
              </div>
              <div class="switch-item">
                <div><strong>默认使用 Staging 测试环境</strong><span>推荐先在测试环境验证域名解析与验证流程，避免触发生产 CA 限流。</span></div>
                <el-switch v-model="form.acme_staging" />
              </div>
            </section>

            <section class="settings-section">
              <div class="section-heading">
                <h3>HTTP-01 验证方式</h3>
                <p>本系统不会修改现有 Nginx / Apache 配置，请根据实际部署选择。</p>
              </div>
              <el-form-item label="验证模式">
                <el-radio-group v-model="form.acme_http01_mode">
                  <el-radio-button label="standalone">内置 Standalone</el-radio-button>
                  <el-radio-button label="webroot">Webroot 目录</el-radio-button>
                </el-radio-group>
              </el-form-item>
              <div v-if="form.acme_http01_mode === 'standalone'" class="form-grid">
                <el-form-item label="监听网卡（可选）">
                  <el-input v-model="form.acme_http01_iface" placeholder="留空监听全部网卡" />
                </el-form-item>
                <el-form-item label="监听端口">
                  <el-input-number v-model="form.acme_http01_port" :min="1" :max="65535" controls-position="right" style="width: 100%" />
                  <div class="form-hint">Let's Encrypt 始终访问公网 80 端口，需要端口映射时请配置转发。</div>
                </el-form-item>
              </div>
              <el-form-item v-else label="Webroot 目录">
                <el-input v-model="form.acme_webroot" placeholder="/var/www/html" />
                <div class="form-hint">验证文件写入 &lt;webroot&gt;/.well-known/acme-challenge/，必须由外部 Web 服务器对公网提供访问。</div>
              </el-form-item>
            </section>

            <section class="settings-section">
              <div class="section-heading">
                <h3>证书部署</h3>
                <p>证书签发后可自动落盘到部署目录，并触发管理员配置的部署脚本。</p>
              </div>
              <div class="switch-item">
                <div><strong>签发成功后自动部署</strong><span>写入 fullchain.pem、privkey.pem（0600）、cert.pem、chain.pem。</span></div>
                <el-switch v-model="form.auto_deploy" />
              </div>
              <div class="form-grid">
                <el-form-item label="部署目录">
                  <el-input v-model="form.deploy_dir" placeholder="./data/deploy" />
                  <div class="form-hint">系统会在该目录下按域名创建子目录，避免任意文件写入。</div>
                </el-form-item>
                <el-form-item label="部署脚本（绝对路径，可选）">
                  <el-input v-model="form.deploy_script" placeholder="/usr/local/bin/reload-nginx.sh" />
                  <div class="form-hint">脚本通过环境变量 CERT_DOMAIN、CERT_DIR、CERT_FULLCHAIN、CERT_PRIVKEY 获取路径，无 Shell 拼接。</div>
                </el-form-item>
              </div>
            </section>

            <div class="save-bar">
              <el-button type="primary" :loading="saving" @click="saveAll">保存 ACME 配置</el-button>
            </div>
          </div>
        </el-tab-pane>

        <el-tab-pane label="备份与恢复" name="backup">
          <div class="settings-body">
            <section class="settings-section">
              <div class="section-heading">
                <h3>系统信息</h3>
                <p>当前运行环境与数据库状态。</p>
              </div>
              <div v-if="system" class="system-grid">
                <div class="system-item"><span>版本</span><strong>{{ system.version }}</strong></div>
                <div class="system-item"><span>Go 版本</span><strong>{{ system.go_version }}</strong></div>
                <div class="system-item"><span>平台</span><strong>{{ system.os }} / {{ system.arch }}</strong></div>
                <div class="system-item"><span>监听地址</span><strong>{{ system.listen }}</strong></div>
                <div class="system-item"><span>运行时长</span><strong>{{ formatUptime(system.uptime_seconds) }}</strong></div>
                <div class="system-item"><span>数据库大小</span><strong>{{ formatBytes(system.database_size) }}</strong></div>
                <div class="system-item"><span>数据库路径</span><strong class="mono">{{ system.database_path }}</strong></div>
                <div class="system-item"><span>ACME 默认环境</span><strong>{{ system.acme_staging ? 'Staging' : 'Production' }}</strong></div>
              </div>
            </section>

            <section class="settings-section">
              <div class="section-heading">
                <h3>备份</h3>
                <p>数据库备份使用 SQLite 在线一致性快照，包含域名、证书元数据、通知渠道与日志，但不含 secret.key、证书私钥和 ACME 账号文件。</p>
              </div>
              <el-checkbox v-model="fullBackup">完整备份（打包 data/ 中的密钥、证书与 ACME 账号）</el-checkbox>
              <div v-if="fullBackup" class="form-hint">
                完整备份会用口令加密。请妥善保存口令；备份文件与口令同时泄露即可解密全部 DNS 凭据和通知密钥。
              </div>
              <el-form-item v-if="fullBackup" label="备份口令" style="margin-top: 12px">
                <el-input v-model="backupPassword" type="password" show-password autocomplete="new-password" placeholder="至少 8 个字符" />
              </el-form-item>
              <div class="save-bar inner">
                <el-button type="primary" :icon="Download" :loading="backingUp" @click="backup">
                  {{ fullBackup ? '下载完整备份' : '下载数据库备份' }}
                </el-button>
              </div>
            </section>

            <section class="settings-section">
              <div class="section-heading">
                <h3>恢复</h3>
                <p>上传 .db 数据库备份或 .dmbak 完整备份。恢复会覆盖当前数据，并强制所有管理员重新登录；恢复期间定时任务会暂停。</p>
              </div>
              <el-alert
                type="warning"
                :closable="false"
                show-icon
                title="完整备份包含敏感密钥"
                description="仅在可信环境恢复完整备份。恢复后 secret.key 会被替换，请确认备份来源可靠。"
                style="margin-bottom: 16px"
              />
              <el-form-item label="完整备份口令（仅 .dmbak 需要）">
                <el-input v-model="restorePassword" type="password" show-password autocomplete="off" placeholder="数据库备份留空即可" />
              </el-form-item>
              <el-upload
                drag
                :auto-upload="false"
                :limit="1"
                accept=".db,.sqlite,.sqlite3,.dmbak,.dmbackup"
                :on-change="onRestoreFile"
                :on-remove="() => (restoreFile = null)"
                :file-list="restoreFileList"
              >
                <el-icon class="el-icon--upload"><UploadFilled /></el-icon>
                <div class="el-upload__text">拖拽 .db / .dmbak 备份到此处，或 <em>点击选择</em></div>
              </el-upload>
              <div class="save-bar inner">
                <el-button type="danger" :icon="Upload" :loading="restoring" :disabled="!restoreFile" @click="restore">
                  恢复数据
                </el-button>
              </div>
            </section>
          </div>
        </el-tab-pane>
      </el-tabs>
    </div>

    <el-dialog
      v-model="totpDialog.visible"
      :title="totpDialog.mode === 'enable' ? '启用二次认证' : totpDialog.mode === 'disable' ? '关闭二次认证' : '重新生成恢复码'"
      width="520px"
      :close-on-click-modal="false"
      :close-on-press-escape="totpDialog.stage !== 'recovery'"
      :show-close="totpDialog.stage !== 'recovery'"
      append-to-body
      @closed="resetTOTPDialog"
    >
      <template v-if="totpDialog.stage === 'form'">
        <p class="totp-dialog-tip">
          {{ totpDialog.mode === 'enable' ? '请先验证当前密码，然后生成新的 TOTP 密钥。' : '请输入当前密码和动态验证码或恢复码以继续。' }}
        </p>
        <el-form label-position="top" @submit.prevent>
          <el-form-item label="当前密码">
            <el-input
              v-model="totpDialog.password"
              type="password"
              show-password
              autocomplete="current-password"
              @keyup.enter="submitTOTPDialog"
            />
          </el-form-item>
          <el-form-item v-if="totpDialog.mode !== 'enable'" label="动态验证码或恢复码">
            <el-input
              v-model="totpDialog.code"
              placeholder="6 位动态验证码，或一次性恢复码"
              autocomplete="one-time-code"
              @keyup.enter="submitTOTPDialog"
            />
          </el-form-item>
        </el-form>
      </template>

      <template v-else-if="totpDialog.stage === 'setup'">
        <el-alert title="使用身份验证器扫描下方二维码" type="info" :closable="false" show-icon />
        <div v-if="totpDialog.qrCode" class="totp-qr">
          <img :src="totpDialog.qrCode" alt="TOTP 二维码" />
        </div>
        <p class="totp-dialog-tip">无法扫描二维码时，可手动输入以下密钥，或复制 otpauth 链接导入：</p>
        <div class="totp-secret-row">
          <code>{{ totpDialog.secret }}</code>
          <el-button link type="primary" @click="copyText(totpDialog.secret)">复制</el-button>
        </div>
        <div class="totp-uri">
          <a :href="totpDialog.otpauth" rel="noreferrer">{{ totpDialog.otpauth }}</a>
          <el-button link type="primary" @click="copyText(totpDialog.otpauth)">复制</el-button>
        </div>
        <el-form label-position="top" @submit.prevent>
          <el-form-item label="输入身份验证器当前生成的 6 位验证码">
            <el-input
              v-model="totpDialog.code"
              maxlength="6"
              placeholder="000000"
              autocomplete="one-time-code"
              @keyup.enter="submitTOTPDialog"
            />
          </el-form-item>
        </el-form>
      </template>

      <template v-else>
        <el-alert title="请立即保存以下恢复码，此列表只显示一次" type="success" :closable="false" show-icon />
        <div class="recovery-grid">
          <code v-for="item in totpDialog.recoveryCodes" :key="item">{{ item }}</code>
        </div>
        <div class="recovery-actions">
          <el-button @click="copyText(totpDialog.recoveryCodes.join('\n'))">复制全部</el-button>
        </div>
      </template>

      <template #footer>
        <el-button @click="totpDialog.visible = false">{{ totpDialog.stage === 'recovery' ? '我已保存，完成' : '取消' }}</el-button>
        <el-button v-if="totpDialog.stage !== 'recovery'" type="primary" :loading="totpDialog.loading" @click="submitTOTPDialog">
          {{ totpDialog.stage === 'setup' ? '确认启用' : totpDialog.mode === 'enable' ? '生成密钥' : totpDialog.mode === 'disable' ? '关闭二次认证' : '重新生成' }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'
import type { FormInstance, FormRules, UploadFile, UploadUserFile } from 'element-plus'
import { Download, Refresh, Upload, UploadFilled } from '@element-plus/icons-vue'
import { api, showError } from '@/api/client'
import type { JobInfo, JobRun, SystemStatus } from '@/api/types'
import { auth, changePassword, clearSession } from '@/stores/auth'
import { downloadBlob, formatBytes, formatDateTime, formatDuration } from '@/utils/status'

const route = useRoute()
const router = useRouter()
const validTabs = ['general', 'scheduler', 'security', 'acme', 'backup']
const activeTab = ref(typeof route.query.tab === 'string' && validTabs.includes(route.query.tab) ? route.query.tab : 'general')
const saving = ref(false)
const system = ref<SystemStatus | null>(null)
const jobs = ref<JobInfo[]>([])
const recentRuns = ref<JobRun[]>([])
const runningJob = ref('')
const backingUp = ref(false)
const restoring = ref(false)
const fullBackup = ref(false)
const backupPassword = ref('')
const restorePassword = ref('')

const timezones = ['Asia/Shanghai', 'Asia/Hong_Kong', 'Asia/Tokyo', 'Asia/Singapore', 'UTC', 'Europe/London', 'America/New_York']

const form = reactive({
  site_name: 'Domain Manager', site_url: '', public_url: '', timezone: 'Asia/Shanghai',
  domain_warning_days: 30, ssl_warning_days: 30,
  domain_thresholds_text: '30, 15, 7, 3, 1, 0', ssl_thresholds_text: '30, 15, 7, 3, 1',
  http_timeout_seconds: 15, rdap_timeout_seconds: 15, max_concurrency: 5, notification_max_retries: 5,
  whois_enabled: true, allow_private_targets: false,
  domain_check_cron: '0 3 * * *', ssl_check_cron: '0 */6 * * *', renewal_check_cron: '0 4 * * *',
  alert_scan_cron: '0 * * * *', notification_retry_cron: '*/10 * * * *', log_retention_days: 90,
  session_ttl_hours: 12, login_max_attempts: 5, login_lock_minutes: 15,
  acme_email: '', acme_key_type: 'rsa2048', acme_renew_days: 30, acme_max_attempts: 3,
  acme_concurrency: 2, acme_renew_cooldown_hours: 24,
  acme_default_dns_provider: 'cloudflare', acme_staging: true,
  acme_http01_mode: 'standalone', acme_http01_iface: '', acme_http01_port: 80, acme_webroot: './data/acme-webroot',
  auto_deploy: false, deploy_dir: './data/deploy', deploy_script: '',
})

const passwordFormRef = ref<FormInstance>()
const changingPassword = ref(false)
const passwordForm = reactive({ current: '', next: '', confirm: '' })
const passwordRules: FormRules = {
  current: [{ required: true, message: '请输入当前密码', trigger: 'blur' }],
  next: [
    { required: true, message: '请输入新密码', trigger: 'blur' },
    { min: 8, message: '新密码至少 8 个字符', trigger: 'blur' },
  ],
  confirm: [{
    validator: (_rule, value, callback) => {
      if (!value) callback(new Error('请再次输入新密码'))
      else if (value !== passwordForm.next) callback(new Error('两次输入的密码不一致'))
      else callback()
    },
    trigger: 'blur',
  }],
}

const totpEnabled = ref(auth.user?.totp_enabled === true)
const totpDialog = reactive({
  visible: false,
  mode: 'enable' as 'enable' | 'disable' | 'regen',
  stage: 'form' as 'form' | 'setup' | 'recovery',
  password: '',
  code: '',
  secret: '',
  otpauth: '',
  qrCode: '',
  recoveryCodes: [] as string[],
  loading: false,
})

function openTOTPDialog(mode: 'enable' | 'disable' | 'regen') {
  totpEnabled.value = auth.user?.totp_enabled === true
  totpDialog.mode = mode
  totpDialog.stage = 'form'
  totpDialog.password = ''
  totpDialog.code = ''
  totpDialog.secret = ''
  totpDialog.otpauth = ''
  totpDialog.qrCode = ''
  totpDialog.recoveryCodes = []
  totpDialog.loading = false
  totpDialog.visible = true
}

function resetTOTPDialog() {
  totpDialog.stage = 'form'
  totpDialog.password = ''
  totpDialog.code = ''
  totpDialog.secret = ''
  totpDialog.otpauth = ''
  totpDialog.qrCode = ''
  totpDialog.recoveryCodes = []
  totpDialog.loading = false
}

async function buildTOTPQRCode(otpauthURL: string) {
  try {
    // Loaded on demand so the QR encoder only ships with the settings page.
    const { default: qrcode } = await import('qrcode-generator')
    const qr = qrcode(0, 'M')
    qr.addData(otpauthURL)
    qr.make()
    return qr.createDataURL(8, 4)
  } catch {
    // Manual secret entry remains available if QR generation fails.
    return ''
  }
}

async function copyText(text: string) {
  if (!text) return
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
      ElMessage.success('已复制')
      return
    }
  } catch {
    // Fall back to execCommand below; clipboard API needs HTTPS.
  }
  const textarea = document.createElement('textarea')
  textarea.value = text
  textarea.style.position = 'fixed'
  textarea.style.opacity = '0'
  document.body.appendChild(textarea)
  textarea.select()
  try {
    document.execCommand('copy')
    ElMessage.success('已复制')
  } catch {
    ElMessage.warning('复制失败，请手动选择文本复制')
  }
  document.body.removeChild(textarea)
}

async function submitTOTPDialog() {
  if (totpDialog.stage === 'form') {
    if (!totpDialog.password) {
      ElMessage.warning('请输入当前密码')
      return
    }
    if (totpDialog.mode !== 'enable' && !totpDialog.code) {
      ElMessage.warning('请输入动态验证码或恢复码')
      return
    }
    totpDialog.loading = true
    try {
      if (totpDialog.mode === 'enable') {
        const data = await api.post<{ secret: string; otpauth_url: string }>('/auth/totp/setup', {
          password: totpDialog.password,
        })
        totpDialog.secret = data.secret
        totpDialog.otpauth = data.otpauth_url
        totpDialog.qrCode = await buildTOTPQRCode(data.otpauth_url)
        totpDialog.code = ''
        totpDialog.stage = 'setup'
      } else if (totpDialog.mode === 'disable') {
        await api.post('/auth/totp/disable', { password: totpDialog.password, code: totpDialog.code })
        totpEnabled.value = false
        if (auth.user) auth.user.totp_enabled = false
        totpDialog.visible = false
        ElMessage.success('二次认证已关闭')
      } else {
        const data = await api.post<{ recovery_codes: string[] }>('/auth/totp/recovery-codes', {
          password: totpDialog.password,
          code: totpDialog.code,
        })
        totpDialog.recoveryCodes = data.recovery_codes
        totpDialog.stage = 'recovery'
      }
    } catch (error) {
      showError(error)
    } finally {
      totpDialog.loading = false
    }
    return
  }

  if (totpDialog.stage === 'setup') {
    if (!totpDialog.code) {
      ElMessage.warning('请输入身份验证器生成的动态验证码')
      return
    }
    totpDialog.loading = true
    try {
      const data = await api.post<{ recovery_codes: string[] }>('/auth/totp/enable', { code: totpDialog.code })
      totpDialog.recoveryCodes = data.recovery_codes
      totpDialog.stage = 'recovery'
      totpEnabled.value = true
      if (auth.user) auth.user.totp_enabled = true
      ElMessage.success('二次认证已启用')
    } catch (error) {
      showError(error)
    } finally {
      totpDialog.loading = false
    }
  }
}

const restoreFile = ref<File | null>(null)
const restoreFileList = ref<UploadUserFile[]>([])

function num(map: Record<string, string>, key: string, fallback: number) {
  const value = Number(map[key])
  return Number.isFinite(value) && value > 0 ? value : fallback
}
function bool(map: Record<string, string>, key: string, fallback: boolean) {
  if (map[key] === undefined) return fallback
  return map[key] === 'true'
}
function thresholdsText(raw: string) {
  try {
    const values = JSON.parse(raw)
    return Array.isArray(values) ? values.join(', ') : raw
  } catch {
    return raw
  }
}

function applySettings(map: Record<string, string>) {
  form.site_name = map.site_name || 'Domain Manager'
  form.site_url = map.site_url || ''
  form.public_url = map.public_url || ''
  form.timezone = map.timezone || 'Asia/Shanghai'
  form.domain_warning_days = num(map, 'domain_warning_days', 30)
  form.ssl_warning_days = num(map, 'ssl_warning_days', 30)
  form.domain_thresholds_text = thresholdsText(map.domain_expiry_thresholds || '[30,15,7,3,1,0]')
  form.ssl_thresholds_text = thresholdsText(map.ssl_expiry_thresholds || '[30,15,7,3,1]')
  form.http_timeout_seconds = num(map, 'http_timeout_seconds', 15)
  form.rdap_timeout_seconds = num(map, 'rdap_timeout_seconds', 15)
  form.max_concurrency = num(map, 'max_concurrency', 5)
  form.notification_max_retries = num(map, 'notification_max_retries', 5)
  form.whois_enabled = bool(map, 'whois_enabled', true)
  form.allow_private_targets = bool(map, 'allow_private_targets', false)
  form.domain_check_cron = map.domain_check_cron || '0 3 * * *'
  form.ssl_check_cron = map.ssl_check_cron || '0 */6 * * *'
  form.renewal_check_cron = map.renewal_check_cron || '0 4 * * *'
  form.alert_scan_cron = map.alert_scan_cron || '0 * * * *'
  form.notification_retry_cron = map.notification_retry_cron || '*/10 * * * *'
  form.log_retention_days = num(map, 'log_retention_days', 90)
  form.session_ttl_hours = num(map, 'session_ttl_hours', 12)
  form.login_max_attempts = num(map, 'login_max_attempts', 5)
  form.login_lock_minutes = num(map, 'login_lock_minutes', 15)
  form.acme_email = map.acme_email || ''
  form.acme_key_type = map.acme_key_type || 'rsa2048'
  form.acme_renew_days = num(map, 'acme_renew_days', 30)
  form.acme_max_attempts = num(map, 'acme_max_attempts', 3)
  form.acme_concurrency = num(map, 'acme_concurrency', 2)
  form.acme_renew_cooldown_hours = num(map, 'acme_renew_cooldown_hours', 24)
  form.acme_default_dns_provider = map.acme_default_dns_provider || 'cloudflare'
  form.acme_staging = bool(map, 'acme_staging', true)
  form.acme_http01_mode = map.acme_http01_mode || 'standalone'
  form.acme_http01_iface = map.acme_http01_iface || ''
  form.acme_http01_port = num(map, 'acme_http01_port', 80)
  form.acme_webroot = map.acme_webroot || './data/acme-webroot'
  form.auto_deploy = bool(map, 'auto_deploy', false)
  form.deploy_dir = map.deploy_dir || './data/deploy'
  form.deploy_script = map.deploy_script || ''
}

function parseThresholds(text: string, label: string): number[] {
  const values = text.split(/[,，\s]+/).filter(Boolean).map(Number)
  if (!values.length || values.some((value) => !Number.isInteger(value) || value < 0 || value > 3650)) {
    throw new Error(`${label}必须是 0-3650 的整数，以逗号分隔`)
  }
  return [...new Set(values)].sort((a, b) => b - a)
}

async function saveAll() {
  let domainThresholds: number[]
  let sslThresholds: number[]
  try {
    domainThresholds = parseThresholds(form.domain_thresholds_text, '域名告警阈值')
    sslThresholds = parseThresholds(form.ssl_thresholds_text, 'SSL 告警阈值')
  } catch (error: any) {
    ElMessage.warning(error.message)
    return
  }
  saving.value = true
  try {
    const payload: Record<string, string> = {
      site_name: form.site_name,
      site_url: form.site_url,
      public_url: form.public_url,
      timezone: form.timezone,
      domain_warning_days: String(form.domain_warning_days),
      ssl_warning_days: String(form.ssl_warning_days),
      domain_expiry_thresholds: JSON.stringify(domainThresholds),
      ssl_expiry_thresholds: JSON.stringify(sslThresholds),
      http_timeout_seconds: String(form.http_timeout_seconds),
      rdap_timeout_seconds: String(form.rdap_timeout_seconds),
      max_concurrency: String(form.max_concurrency),
      notification_max_retries: String(form.notification_max_retries),
      whois_enabled: String(form.whois_enabled),
      allow_private_targets: String(form.allow_private_targets),
      domain_check_cron: form.domain_check_cron,
      ssl_check_cron: form.ssl_check_cron,
      renewal_check_cron: form.renewal_check_cron,
      alert_scan_cron: form.alert_scan_cron,
      notification_retry_cron: form.notification_retry_cron,
      log_retention_days: String(form.log_retention_days),
      session_ttl_hours: String(form.session_ttl_hours),
      login_max_attempts: String(form.login_max_attempts),
      login_lock_minutes: String(form.login_lock_minutes),
      acme_email: form.acme_email,
      acme_key_type: form.acme_key_type,
      acme_renew_days: String(form.acme_renew_days),
      acme_max_attempts: String(form.acme_max_attempts),
      acme_concurrency: String(form.acme_concurrency),
      acme_renew_cooldown_hours: String(form.acme_renew_cooldown_hours),
      acme_default_dns_provider: form.acme_default_dns_provider,
      acme_staging: String(form.acme_staging),
      acme_http01_mode: form.acme_http01_mode,
      acme_http01_iface: form.acme_http01_iface,
      acme_http01_port: String(form.acme_http01_port),
      acme_webroot: form.acme_webroot,
      auto_deploy: String(form.auto_deploy),
      deploy_dir: form.deploy_dir,
      deploy_script: form.deploy_script,
    }
    const result = await api.put<{ settings: Record<string, string>; warning: string }>('/settings', { settings: payload })
    applySettings(result.settings)
    if (result.warning) ElMessage.warning(result.warning)
    else ElMessage.success('设置已保存')
    if (activeTab.value === 'scheduler') loadJobs()
  } catch (error) {
    showError(error)
  } finally {
    saving.value = false
  }
}

async function submitPassword() {
  if (!passwordFormRef.value) return
  const valid = await passwordFormRef.value.validate().catch(() => false)
  if (!valid) return
  changingPassword.value = true
  try {
    await changePassword(passwordForm.current, passwordForm.next)
    ElMessage.success('密码已修改，请使用新密码重新登录')
    await router.replace('/login')
  } catch (error) {
    showError(error)
  } finally {
    changingPassword.value = false
  }
}

async function loadSettings() {
  try {
    const data = await api.get<{ settings: Record<string, string> }>('/settings')
    applySettings(data.settings)
  } catch (error) {
    showError(error)
  }
}

async function loadSystem() {
  try {
    system.value = await api.get<SystemStatus>('/system/status')
  } catch {
    // Status panel is non-critical.
  }
}

async function loadJobs() {
  try {
    const data = await api.get<{ jobs: JobInfo[]; recent_runs: JobRun[] }>('/jobs')
    jobs.value = data.jobs
    recentRuns.value = data.recent_runs
  } catch (error) {
    showError(error)
  }
}

async function runJob(job: JobInfo) {
  try {
    await ElMessageBox.confirm(`确定立即执行任务「${job.name}」吗？`, '执行定时任务', {
      confirmButtonText: '执行', cancelButtonText: '取消', type: 'info',
    })
  } catch {
    return
  }
  runningJob.value = job.key
  try {
    await api.post(`/jobs/${job.key}/run`)
    ElMessage.success('任务已触发，稍后刷新查看结果')
    setTimeout(loadJobs, 2500)
  } catch (error) {
    showError(error)
  } finally {
    runningJob.value = ''
  }
}

async function backup() {
  if (fullBackup.value && backupPassword.value.length < 8) {
    ElMessage.warning('完整备份口令至少需要 8 个字符')
    return
  }
  backingUp.value = true
  try {
    const blob = await api.postBlob(
      '/system/backup',
      fullBackup.value ? { full: true, password: backupPassword.value } : {},
    )
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')
    const suffix = fullBackup.value ? 'dmbak' : 'db'
    downloadBlob(blob, `domain-manager-backup-${stamp}.${suffix}`)
    ElMessage.success(fullBackup.value ? '完整备份已下载' : '数据库备份已下载')
  } catch (error) {
    showError(error)
  } finally {
    backingUp.value = false
  }
}

function onRestoreFile(file: UploadFile) {
  restoreFile.value = file.raw || null
  restoreFileList.value = file.raw ? [{ name: file.name, raw: file.raw, status: 'ready' } as UploadUserFile] : []
}

async function restore() {
  if (!restoreFile.value) return
  try {
    await ElMessageBox.confirm(
      '恢复将覆盖当前数据，并强制所有管理员重新登录。完整备份还会替换 secret.key 与证书文件。此操作不可撤销，是否继续？',
      '确认恢复数据',
      { confirmButtonText: '确认恢复', cancelButtonText: '取消', type: 'warning' },
    )
  } catch {
    return
  }
  restoring.value = true
  try {
    const formData = new FormData()
    formData.append('file', restoreFile.value)
    if (restorePassword.value) formData.append('password', restorePassword.value)
    await api.upload('/system/restore', formData)
    clearSession()
    ElMessage.success('数据已恢复，请重新登录')
    await router.replace('/login')
  } catch (error) {
    showError(error)
  } finally {
    restoring.value = false
  }
}

function formatUptime(seconds: number) {
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  if (days > 0) return `${days} 天 ${hours} 小时`
  if (hours > 0) return `${hours} 小时 ${minutes} 分钟`
  return `${minutes} 分钟`
}

onMounted(async () => {
  if (auth.user?.must_change_password) {
    activeTab.value = 'security'
    return
  }
  await Promise.all([loadSettings(), loadSystem(), loadJobs()])
})
</script>

<style scoped>
.settings-panel {
  overflow: hidden;
}
.settings-tabs :deep(.el-tabs__header) {
  margin: 0;
  padding: 0 22px;
  border-bottom: 1px solid var(--dm-border);
}
.settings-tabs :deep(.el-tabs__item) {
  height: 54px;
  font-weight: 600;
}
.settings-body {
  padding: 8px 24px 24px;
  max-width: 1050px;
}
.settings-section {
  padding: 24px 0;
  border-bottom: 1px solid var(--dm-border);
}
.settings-section:last-of-type {
  border-bottom: 0;
}
.section-heading {
  margin-bottom: 18px;
}
.section-heading h3 {
  margin: 0;
  font-size: 15px;
  font-weight: 650;
}
.section-heading p {
  margin: 5px 0 0;
  color: var(--dm-text-muted);
  font-size: 12px;
  line-height: 1.6;
}
.row-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}
.form-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0 20px;
}
.switch-list {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--dm-border);
  border-radius: 12px;
  overflow: hidden;
}
.switch-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  padding: 14px 16px;
  border-bottom: 1px solid var(--dm-border);
  background: var(--dm-panel-2);
}
.switch-item:last-child {
  border-bottom: 0;
}
.switch-item > div {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.switch-item strong {
  font-size: 12.5px;
}
.switch-item span {
  color: var(--dm-text-muted);
  font-size: 11px;
  line-height: 1.55;
}
.danger-text {
  color: var(--dm-danger);
}
.section-alert {
  margin-top: 14px;
}
.save-bar {
  padding-top: 20px;
  display: flex;
  justify-content: flex-end;
}
.save-bar.inner {
  padding-top: 16px;
}
.cron-input :deep(input) {
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 12px;
}
.job-name {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.job-name strong {
  font-size: 12px;
}
.job-name span {
  color: var(--dm-text-muted);
  font-size: 10px;
}
.run-history {
  margin-top: 18px;
  border-top: 1px solid var(--dm-border);
  padding-top: 16px;
}
.run-history h4 {
  font-size: 12px;
  margin: 0 0 10px;
  color: var(--dm-text-secondary);
}
.run-row {
  display: grid;
  grid-template-columns: 70px 100px minmax(0, 1fr) 160px;
  align-items: center;
  gap: 10px;
  padding: 7px 0;
  font-size: 11px;
  border-bottom: 1px dashed var(--dm-border);
}
.run-row span:nth-child(3) {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--dm-text-secondary);
}
.password-form {
  max-width: 420px;
}
.totp-status {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
  padding: 14px;
  border: 1px solid var(--dm-border);
  border-radius: 10px;
  background: var(--dm-panel-2);
}
.totp-status-text {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  color: var(--dm-text-muted);
  font-size: 12px;
}
.totp-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
.totp-dialog-tip {
  color: var(--dm-text-muted);
  font-size: 12px;
  line-height: 1.7;
  margin: 0 0 16px;
}
.totp-qr {
  display: flex;
  justify-content: center;
  margin: 14px 0;
  padding: 14px;
  border: 1px solid var(--dm-border);
  border-radius: 12px;
  background: #fff;
}
.totp-qr img {
  display: block;
  width: min(232px, 100%);
  height: auto;
  image-rendering: pixelated;
}
.totp-secret-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin: 14px 0;
  padding: 12px 14px;
  border: 1px dashed var(--dm-border);
  border-radius: 10px;
  background: var(--dm-panel-2);
  overflow: auto;
}
.totp-secret-row code {
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
  font-size: 13px;
  letter-spacing: 0.06em;
  word-break: break-all;
}
.totp-uri {
  display: flex;
  gap: 8px;
  align-items: flex-start;
  margin-bottom: 16px;
}
.totp-uri a {
  color: var(--dm-primary);
  font-size: 11px;
  line-height: 1.6;
  word-break: break-all;
}
.recovery-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px;
  margin: 16px 0;
}
.recovery-grid code {
  padding: 8px 10px;
  border: 1px solid var(--dm-border);
  border-radius: 8px;
  background: var(--dm-panel-2);
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
  font-size: 12px;
  letter-spacing: 0.04em;
  text-align: center;
}
.recovery-actions {
  text-align: right;
}
.system-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}
.system-item {
  border: 1px solid var(--dm-border);
  background: var(--dm-panel-2);
  border-radius: 10px;
  padding: 12px 14px;
  display: flex;
  flex-direction: column;
  gap: 5px;
  min-width: 0;
}
.system-item span {
  font-size: 10.5px;
  color: var(--dm-text-muted);
}
.system-item strong {
  font-size: 12px;
  font-weight: 600;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
@media (max-width: 800px) {
  .form-grid, .system-grid {
    grid-template-columns: 1fr;
  }
  .settings-body {
    padding: 8px 16px 20px;
  }
  .run-row {
    grid-template-columns: 60px 1fr;
  }
  .run-row span:nth-child(4) { display: none; }
}
</style>
