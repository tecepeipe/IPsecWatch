using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Xml.Serialization;

namespace IpsecWatch
{
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }

    [Serializable]
    public class AppSettings
    {
        public bool MonitoringEnabled = true;
        public bool StartWithWindows = false;
        public List<MonitorTarget> Targets = new List<MonitorTarget>();
    }

    [Serializable]
    public class MonitorTarget
    {
        public string Id = Guid.NewGuid().ToString("N");
        public string Name = "Novo túnel";
        public string Host = "";
        public string PeerEndpoint = "";
        public string SourceAddress = "10.69.69.1";
        public string ProbeType = "TCP";
        public int TcpPort = 443;
        public int IntervalSeconds = 30;
        public int TimeoutMs = 2000;
        public bool Enabled = true;

        [XmlIgnore] public DateTime NextCheck = DateTime.MinValue;
        [XmlIgnore] public DateTime LastCheck = DateTime.MinValue;
        [XmlIgnore] public bool Running;
        [XmlIgnore] public bool? Reachable;
        [XmlIgnore] public long RoundtripMs;
        [XmlIgnore] public string LastError = "";
    }

    internal class SaRow
    {
        public string Mode;
        public string Direction;
        public string Local;
        public string Remote;
        public string Algorithm;
        public string Ike;
        public string InterfaceName;
        public string FilterName;
        public string Idle;
        public string Lifetime;
    }

    internal class ProbeResult
    {
        public bool Success;
        public long RoundtripMs;
        public string Error;
    }

    public sealed class MainForm : Form
    {
        private const string FixedSourceAddress = "10.69.69.1";
        private readonly string settingsDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "IpsecWatch");
        private readonly BindingList<MonitorTarget> targets = new BindingList<MonitorTarget>();
        private readonly List<SaRow> sas = new List<SaRow>();
        private readonly Timer scheduler = new Timer();
        private readonly Timer saTimer = new Timer();
        private readonly DataGridView monitorGrid = new DataGridView();
        private readonly DataGridView saGrid = new DataGridView();
        private readonly ToolStripStatusLabel statusLabel = new ToolStripStatusLabel();
        private readonly ToolStripStatusLabel saCountLabel = new ToolStripStatusLabel();
        private readonly NotifyIcon tray = new NotifyIcon();
        private readonly Button toggleButton = new Button();
        private readonly CheckBox startupCheck = new CheckBox();
        private AppSettings settings;
        private bool reallyExit;
        private bool refreshingSas;
        private bool changingStartup;

        public MainForm()
        {
            Text = "IPsec Watch";
            Icon = SystemIcons.Shield;
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(940, 560);
            Size = new Size(1120, 680);
            Font = new Font("Segoe UI", 9F);

            settings = LoadSettings();
            foreach (MonitorTarget target in settings.Targets)
            {
                Normalize(target);
                targets.Add(target);
            }

            BuildUi();
            ConfigureTray();

            scheduler.Interval = 1000;
            scheduler.Tick += SchedulerTick;
            scheduler.Start();

            saTimer.Interval = 10000;
            saTimer.Tick += async delegate { await RefreshSasAsync(); };
            saTimer.Start();

            Shown += async delegate
            {
                RefreshMonitorGrid();
                await RefreshSasAsync();
            };
            FormClosing += OnFormClosing;
            Resize += delegate
            {
                if (WindowState == FormWindowState.Minimized)
                {
                    Hide();
                    tray.ShowBalloonTip(1200, "IPsec Watch", "Monitoramento continua na bandeja.", ToolTipIcon.Info);
                }
            };
        }

        private void BuildUi()
        {
            var tabs = new TabControl { Dock = DockStyle.Fill };
            tabs.TabPages.Add(BuildMonitorTab());
            tabs.TabPages.Add(BuildSaTab());
            tabs.TabPages.Add(BuildHelpTab());

            var status = new StatusStrip();
            status.Items.Add(statusLabel);
            status.Items.Add(new ToolStripStatusLabel { Spring = true });
            status.Items.Add(saCountLabel);

            Controls.Add(tabs);
            Controls.Add(status);
            UpdateStatus();
        }

        private TabPage BuildMonitorTab()
        {
            var page = new TabPage("Monitores / keepalive");
            var bar = new FlowLayoutPanel
            {
                Dock = DockStyle.Top,
                Height = 48,
                Padding = new Padding(8, 8, 8, 4),
                WrapContents = false
            };

            Button add = MakeButton("Adicionar", delegate { AddTarget(); });
            Button edit = MakeButton("Editar", delegate { EditSelected(); });
            Button remove = MakeButton("Remover", delegate { RemoveSelected(); });
            Button test = MakeButton("Testar agora", async delegate { await TestSelectedAsync(); });
            toggleButton.Text = settings.MonitoringEnabled ? "Pausar" : "Iniciar";
            toggleButton.AutoSize = true;
            toggleButton.Height = 30;
            toggleButton.Click += delegate
            {
                settings.MonitoringEnabled = !settings.MonitoringEnabled;
                toggleButton.Text = settings.MonitoringEnabled ? "Pausar" : "Iniciar";
                SaveSettings();
                UpdateStatus();
            };
            startupCheck.Text = "Iniciar com o Windows";
            startupCheck.AutoSize = true;
            startupCheck.Margin = new Padding(20, 7, 0, 0);
            startupCheck.Checked = settings.StartWithWindows;
            startupCheck.CheckedChanged += delegate { SetStartup(startupCheck.Checked); };
            bar.Controls.AddRange(new Control[] { add, edit, remove, test, toggleButton, startupCheck });

            ConfigureGrid(monitorGrid);
            monitorGrid.CellDoubleClick += delegate { EditSelected(); };
            monitorGrid.Columns.Add(CheckColumn("Enabled", "Ativo", 55));
            monitorGrid.Columns.Add(TextColumn("Name", "Nome", 150));
            monitorGrid.Columns.Add(TextColumn("Host", "Destino", 135));
            monitorGrid.Columns.Add(TextColumn("Probe", "Teste", 75));
            monitorGrid.Columns.Add(TextColumn("Source", "IP de origem", 105));
            monitorGrid.Columns.Add(TextColumn("PeerEndpoint", "Peer público", 125));
            monitorGrid.Columns.Add(TextColumn("PingState", "Resultado", 95));
            monitorGrid.Columns.Add(TextColumn("Rtt", "RTT", 65));
            monitorGrid.Columns.Add(TextColumn("IpsecState", "IPsec", 90));
            monitorGrid.Columns.Add(TextColumn("LastCheckText", "Último teste", 130));
            monitorGrid.Columns.Add(TextColumn("IntervalText", "Intervalo", 80));
            monitorGrid.CellFormatting += MonitorCellFormatting;
            monitorGrid.CellContentClick += delegate(object sender, DataGridViewCellEventArgs e)
            {
                if (e.RowIndex >= 0 && e.ColumnIndex == 0)
                {
                    MonitorTarget t = monitorGrid.Rows[e.RowIndex].Tag as MonitorTarget;
                    if (t != null)
                    {
                        t.Enabled = !t.Enabled;
                        t.NextCheck = DateTime.MinValue;
                        SaveSettings();
                        RefreshMonitorGrid();
                    }
                }
            };

            var info = new Label
            {
                Dock = DockStyle.Bottom,
                Height = 42,
                Padding = new Padding(10, 7, 10, 0),
                ForeColor = Color.DimGray,
                Text = "O destino deve estar atrás do túnel. A sondagem TCP usa explicitamente o IP de origem configurado " +
                       "e gera tráfego que pode disparar e manter uma VPN sob demanda."
            };
            page.Controls.Add(monitorGrid);
            page.Controls.Add(info);
            page.Controls.Add(bar);
            return page;
        }

        private TabPage BuildSaTab()
        {
            var page = new TabPage("SAs IPsec ativas");
            var bar = new FlowLayoutPanel
            {
                Dock = DockStyle.Top,
                Height = 48,
                Padding = new Padding(8, 8, 8, 4)
            };
            bar.Controls.Add(MakeButton("Atualizar agora", async delegate { await RefreshSasAsync(); }));
            var hint = new Label
            {
                AutoSize = true,
                Margin = new Padding(16, 7, 0, 0),
                ForeColor = Color.DimGray,
                Text = "Atualização automática a cada 10 segundos"
            };
            bar.Controls.Add(hint);

            ConfigureGrid(saGrid);
            saGrid.Columns.Add(TextColumn("Mode", "Modo", 85));
            saGrid.Columns.Add(TextColumn("Direction", "Direção", 80));
            saGrid.Columns.Add(TextColumn("Local", "Endpoint local", 130));
            saGrid.Columns.Add(TextColumn("Remote", "Endpoint remoto", 130));
            saGrid.Columns.Add(TextColumn("Algorithm", "Criptografia", 110));
            saGrid.Columns.Add(TextColumn("Ike", "IKE/PFS", 80));
            saGrid.Columns.Add(TextColumn("InterfaceName", "Interface", 100));
            saGrid.Columns.Add(TextColumn("FilterName", "Filtro/túnel", 220));
            saGrid.Columns.Add(TextColumn("Idle", "Ocioso", 65));
            saGrid.Columns.Add(TextColumn("Lifetime", "Lifetime", 70));

            page.Controls.Add(saGrid);
            page.Controls.Add(bar);
            return page;
        }

        private TabPage BuildHelpTab()
        {
            var page = new TabPage("Como usar");
            var text = new TextBox
            {
                Dock = DockStyle.Fill,
                Multiline = true,
                ReadOnly = true,
                BorderStyle = BorderStyle.None,
                BackColor = SystemColors.Window,
                Font = new Font("Segoe UI", 10F),
                ScrollBars = ScrollBars.Vertical,
                Text =
                    "COMO CONFIGURAR\r\n\r\n" +
                    "1. Clique em Adicionar.\r\n" +
                    "2. Informe o host interno e a porta TCP real de um serviço atrás da VPN.\r\n" +
                    "3. O IP de origem padrão é 10.69.69.1; ele precisa existir em uma interface deste Windows.\r\n" +
                    "4. Se souber o IP público do peer, informe-o para correlacionar o monitor com a SA IPsec.\r\n" +
                    "5. Escolha o intervalo. De 20 a 60 segundos costuma ser suficiente.\r\n\r\n" +
                    "A sondagem TCP cria uma conexão curta a partir do IP de origem e a fecha imediatamente. " +
                    "Isso funciona mesmo quando o destino bloqueia ICMP. Se a porta recusar ou expirar, o pacote de saída " +
                    "ainda pode disparar o túnel; confira a aba de SAs para confirmar a negociação.\r\n\r\n" +
                    "O campo Peer público é opcional e serve somente para mostrar Ativo/Inativo na primeira aba. " +
                    "A fonte oficial do estado é a aba SAs IPsec ativas.\r\n\r\n" +
                    "O aplicativo não altera políticas IPsec, não armazena credenciais e não reinicia serviços. " +
                    "Ele consulta Get-NetIPsecMainModeSA / Get-NetIPsecQuickModeSA e gera tráfego para os hosts configurados.\r\n\r\n" +
                    "Fechar ou minimizar envia o aplicativo para a bandeja. Use o menu do ícone para sair de verdade."
            };
            text.Select(0, 0);
            page.Padding = new Padding(14);
            page.Controls.Add(text);
            return page;
        }

        private static Button MakeButton(string text, EventHandler click)
        {
            var button = new Button { Text = text, AutoSize = true, Height = 30 };
            button.Click += click;
            return button;
        }

        private static DataGridViewTextBoxColumn TextColumn(string name, string title, int width)
        {
            return new DataGridViewTextBoxColumn
            {
                Name = name,
                HeaderText = title,
                Width = width,
                ReadOnly = true,
                SortMode = DataGridViewColumnSortMode.Automatic
            };
        }

        private static DataGridViewCheckBoxColumn CheckColumn(string name, string title, int width)
        {
            return new DataGridViewCheckBoxColumn
            {
                Name = name,
                HeaderText = title,
                Width = width,
                ReadOnly = true
            };
        }

        private static void ConfigureGrid(DataGridView grid)
        {
            grid.Dock = DockStyle.Fill;
            grid.AllowUserToAddRows = false;
            grid.AllowUserToDeleteRows = false;
            grid.AllowUserToResizeRows = false;
            grid.RowHeadersVisible = false;
            grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            grid.MultiSelect = false;
            grid.AutoGenerateColumns = false;
            grid.BackgroundColor = SystemColors.Window;
            grid.BorderStyle = BorderStyle.Fixed3D;
            grid.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(247, 249, 252);
        }

        private void ConfigureTray()
        {
            var menu = new ContextMenuStrip();
            menu.Items.Add("Abrir", null, delegate { RestoreWindow(); });
            menu.Items.Add("Testar todos agora", null, async delegate { await TestAllAsync(); });
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Sair", null, delegate
            {
                reallyExit = true;
                tray.Visible = false;
                Close();
            });
            tray.Icon = SystemIcons.Shield;
            tray.Text = "IPsec Watch";
            tray.Visible = true;
            tray.ContextMenuStrip = menu;
            tray.DoubleClick += delegate { RestoreWindow(); };
        }

        private void RestoreWindow()
        {
            Show();
            WindowState = FormWindowState.Normal;
            Activate();
        }

        private void OnFormClosing(object sender, FormClosingEventArgs e)
        {
            if (!reallyExit && e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                Hide();
                tray.ShowBalloonTip(1200, "IPsec Watch", "Monitoramento continua na bandeja.", ToolTipIcon.Info);
            }
            else
            {
                tray.Visible = false;
                SaveSettings();
            }
        }

        private void AddTarget()
        {
            var target = new MonitorTarget();
            using (var dialog = new TargetDialog(target))
            {
                if (dialog.ShowDialog(this) == DialogResult.OK)
                {
                    targets.Add(target);
                    settings.Targets.Add(target);
                    SaveSettings();
                    RefreshMonitorGrid();
                }
            }
        }

        private MonitorTarget SelectedTarget()
        {
            if (monitorGrid.SelectedRows.Count == 0) return null;
            return monitorGrid.SelectedRows[0].Tag as MonitorTarget;
        }

        private void EditSelected()
        {
            MonitorTarget target = SelectedTarget();
            if (target == null) return;
            using (var dialog = new TargetDialog(target))
            {
                if (dialog.ShowDialog(this) == DialogResult.OK)
                {
                    target.NextCheck = DateTime.MinValue;
                    SaveSettings();
                    RefreshMonitorGrid();
                }
            }
        }

        private void RemoveSelected()
        {
            MonitorTarget target = SelectedTarget();
            if (target == null) return;
            if (MessageBox.Show(this, "Remover o monitor '" + target.Name + "'?", "IPsec Watch",
                MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            targets.Remove(target);
            settings.Targets.Remove(target);
            SaveSettings();
            RefreshMonitorGrid();
        }

        private async void SchedulerTick(object sender, EventArgs e)
        {
            if (!settings.MonitoringEnabled) return;
            List<MonitorTarget> due = targets.Where(t => t.Enabled && !t.Running && DateTime.Now >= t.NextCheck).ToList();
            foreach (MonitorTarget target in due) RunPingAsync(target);
            await Task.FromResult(0);
        }

        private async void RunPingAsync(MonitorTarget target)
        {
            if (target.Running || String.IsNullOrWhiteSpace(target.Host)) return;
            target.Running = true;
            target.NextCheck = DateTime.Now.AddSeconds(Math.Max(5, target.IntervalSeconds));
            try
            {
                ProbeResult result = await Task.Run(delegate { return RunProbe(target); });
                target.Reachable = result.Success;
                target.RoundtripMs = result.RoundtripMs;
                target.LastError = result.Error ?? "";
            }
            catch (Exception ex)
            {
                target.Reachable = false;
                target.RoundtripMs = 0;
                target.LastError = ex.GetBaseException().Message;
            }
            finally
            {
                target.LastCheck = DateTime.Now;
                target.Running = false;
                if (!IsDisposed) BeginInvoke((Action)delegate { RefreshMonitorGrid(); UpdateStatus(); });
            }
        }

        private static ProbeResult RunProbe(MonitorTarget target)
        {
            const string sourceIp = "10.69.69.1";
            var stopwatch = Stopwatch.StartNew();
            if (String.Equals(target.ProbeType, "ICMP", StringComparison.OrdinalIgnoreCase))
            {
                if (!String.IsNullOrWhiteSpace(sourceIp))
                {
                    var start = new ProcessStartInfo
                    {
                        FileName = "ping.exe",
                        Arguments = "-n 1 -w " + target.TimeoutMs + " -S " + sourceIp + " " + target.Host.Trim(),
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };
                    using (Process process = Process.Start(start))
                    {
                        process.StandardOutput.ReadToEnd();
                        process.StandardError.ReadToEnd();
                        process.WaitForExit(target.TimeoutMs + 2000);
                        if (!process.HasExited) process.Kill();
                        stopwatch.Stop();
                        return new ProbeResult
                        {
                            Success = process.HasExited && process.ExitCode == 0,
                            RoundtripMs = stopwatch.ElapsedMilliseconds,
                            Error = process.HasExited && process.ExitCode == 0 ? "" : "Sem resposta ICMP"
                        };
                    }
                }
                using (var ping = new Ping())
                {
                    PingReply reply = ping.Send(target.Host.Trim(), target.TimeoutMs);
                    stopwatch.Stop();
                    bool success = reply != null && reply.Status == IPStatus.Success;
                    return new ProbeResult
                    {
                        Success = success,
                        RoundtripMs = success ? reply.RoundtripTime : stopwatch.ElapsedMilliseconds,
                        Error = success ? "" : (reply == null ? "Sem resposta ICMP" : reply.Status.ToString())
                    };
                }
            }

            IPAddress sourceAddress;
            if (!IPAddress.TryParse(sourceIp, out sourceAddress))
                throw new Exception("IP de origem fixo inválido: " + sourceIp);
            IPAddress remoteAddress = Dns.GetHostAddresses(target.Host.Trim())
                .FirstOrDefault(address => address.AddressFamily == sourceAddress.AddressFamily);
            if (remoteAddress == null)
                throw new Exception("O destino não possui endereço compatível com " + sourceAddress.AddressFamily);

            using (var socket = new Socket(remoteAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp))
            {
                socket.Bind(new IPEndPoint(sourceAddress, 0));
                IAsyncResult pending = socket.BeginConnect(new IPEndPoint(remoteAddress, target.TcpPort), null, null);
                bool connected = pending.AsyncWaitHandle.WaitOne(target.TimeoutMs);
                if (!connected)
                {
                    socket.Close();
                    throw new TimeoutException("Timeout TCP em " + target.Host + ":" + target.TcpPort);
                }
                socket.EndConnect(pending);
                stopwatch.Stop();
                return new ProbeResult { Success = true, RoundtripMs = stopwatch.ElapsedMilliseconds, Error = "" };
            }
        }

        private async Task TestSelectedAsync()
        {
            MonitorTarget target = SelectedTarget();
            if (target == null) return;
            target.NextCheck = DateTime.MinValue;
            RunPingAsync(target);
            await Task.FromResult(0);
        }

        private async Task TestAllAsync()
        {
            foreach (MonitorTarget target in targets.Where(t => t.Enabled))
            {
                target.NextCheck = DateTime.MinValue;
                RunPingAsync(target);
            }
            await Task.FromResult(0);
        }

        private async Task RefreshSasAsync()
        {
            if (refreshingSas) return;
            refreshingSas = true;
            try
            {
                List<SaRow> rows = await Task.Run(delegate { return ReadSas(); });
                sas.Clear();
                sas.AddRange(rows);
                RefreshSaGrid();
                RefreshMonitorGrid();
                saCountLabel.Text = sas.Count + " SA(s) IPsec";
            }
            catch (Exception ex)
            {
                saCountLabel.Text = "Erro ao consultar IPsec: " + ex.Message;
            }
            finally
            {
                refreshingSas = false;
            }
        }

        private static List<SaRow> ReadSas()
        {
            const string ps =
                "$ErrorActionPreference='Stop'; $s=[char]31; " +
                "Get-NetIPsecMainModeSA | % { @('Main','-',[string]$_.LocalEndpoint,[string]$_.RemoteEndpoint," +
                "[string]$_.CipherAlgorithm,[string]$_.KeyModule,'','',[string]$_.IdleDurationSeconds,[string]$_.LifetimeSeconds) -join $s }; " +
                "Get-NetIPsecQuickModeSA | % { @('Quick',[string]$_.Direction,[string]$_.LocalEndpoint,[string]$_.RemoteEndpoint," +
                "[string]$_.FirstCipherAlgorithm,[string]$_.PfsGroupId,[string]$_.InterfaceAlias,[string]$_.TransportLayerFilterName," +
                "[string]$_.IdleDurationSeconds,[string]$_.LifetimeSeconds) -join $s }";
            string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(ps));
            var start = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8
            };
            using (Process process = Process.Start(start))
            {
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit(8000);
                if (!process.HasExited)
                {
                    process.Kill();
                    throw new Exception("tempo limite excedido");
                }
                if (process.ExitCode != 0) throw new Exception(LastUsefulLine(error));
                var result = new List<SaRow>();
                foreach (string line in output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
                {
                    string[] p = line.Split((char)31);
                    if (p.Length < 10) continue;
                    result.Add(new SaRow
                    {
                        Mode = p[0], Direction = p[1], Local = p[2], Remote = p[3],
                        Algorithm = p[4], Ike = p[5], InterfaceName = p[6], FilterName = p[7],
                        Idle = FormatSeconds(p[8]), Lifetime = FormatSeconds(p[9])
                    });
                }
                return result;
            }
        }

        private static string LastUsefulLine(string text)
        {
            string[] lines = (text ?? "").Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            return lines.Length == 0 ? "falha desconhecida" : lines[lines.Length - 1].Trim();
        }

        private static string FormatSeconds(string value)
        {
            int seconds;
            if (!Int32.TryParse(value, out seconds)) return value;
            if (seconds >= 3600) return (seconds / 3600) + "h";
            if (seconds >= 60) return (seconds / 60) + "m";
            return seconds + "s";
        }

        private void RefreshMonitorGrid()
        {
            string selectedId = SelectedTarget() == null ? null : SelectedTarget().Id;
            monitorGrid.Rows.Clear();
            foreach (MonitorTarget target in targets)
            {
                bool? ipsec = PeerState(target.PeerEndpoint);
                int index = monitorGrid.Rows.Add(
                    target.Enabled,
                    target.Name,
                    target.Host,
                    String.Equals(target.ProbeType, "ICMP", StringComparison.OrdinalIgnoreCase) ? "ICMP" : "TCP/" + target.TcpPort,
                    target.SourceAddress,
                    target.PeerEndpoint,
                    target.Running ? "Testando..." : !target.Reachable.HasValue ? "Aguardando" : target.Reachable.Value ? "Online" : "Sem resposta",
                    target.Reachable == true ? target.RoundtripMs + " ms" : "-",
                    !ipsec.HasValue ? "-" : ipsec.Value ? "Ativo" : "Inativo",
                    target.LastCheck == DateTime.MinValue ? "-" : target.LastCheck.ToString("dd/MM HH:mm:ss"),
                    target.IntervalSeconds + " s");
                monitorGrid.Rows[index].Tag = target;
                monitorGrid.Rows[index].Cells[6].ToolTipText = target.LastError;
                if (target.Id == selectedId) monitorGrid.Rows[index].Selected = true;
            }
        }

        private bool? PeerState(string peer)
        {
            if (String.IsNullOrWhiteSpace(peer)) return null;
            string normalized = peer.Trim();
            return sas.Any(sa => String.Equals(sa.Remote, normalized, StringComparison.OrdinalIgnoreCase));
        }

        private void MonitorCellFormatting(object sender, DataGridViewCellFormattingEventArgs e)
        {
            if (e.RowIndex < 0 || e.ColumnIndex < 0) return;
            string column = monitorGrid.Columns[e.ColumnIndex].Name;
            string value = Convert.ToString(e.Value);
            if ((column == "PingState" && value == "Online") || (column == "IpsecState" && value == "Ativo"))
            {
                e.CellStyle.ForeColor = Color.DarkGreen;
                e.CellStyle.Font = new Font(monitorGrid.Font, FontStyle.Bold);
            }
            else if ((column == "PingState" && value == "Sem resposta") || (column == "IpsecState" && value == "Inativo"))
            {
                e.CellStyle.ForeColor = Color.Firebrick;
                e.CellStyle.Font = new Font(monitorGrid.Font, FontStyle.Bold);
            }
        }

        private void RefreshSaGrid()
        {
            saGrid.Rows.Clear();
            foreach (SaRow sa in sas)
            {
                int index = saGrid.Rows.Add(sa.Mode, sa.Direction, sa.Local, sa.Remote, sa.Algorithm,
                    sa.Ike, sa.InterfaceName, sa.FilterName, sa.Idle, sa.Lifetime);
                if (sa.Mode == "Main") saGrid.Rows[index].DefaultCellStyle.BackColor = Color.FromArgb(232, 244, 255);
            }
        }

        private void UpdateStatus()
        {
            if (!settings.MonitoringEnabled)
            {
                statusLabel.Text = "Monitoramento pausado";
                statusLabel.ForeColor = Color.DarkOrange;
                return;
            }
            int online = targets.Count(t => t.Enabled && t.Reachable == true);
            int enabled = targets.Count(t => t.Enabled);
            statusLabel.Text = "Monitoramento ativo — " + online + "/" + enabled + " host(s) respondendo";
            statusLabel.ForeColor = Color.DarkGreen;
        }

        private AppSettings LoadSettings()
        {
            string file = Path.Combine(settingsDir, "settings.xml");
            try
            {
                if (!File.Exists(file)) return new AppSettings();
                using (var stream = File.OpenRead(file))
                    return (AppSettings)new XmlSerializer(typeof(AppSettings)).Deserialize(stream);
            }
            catch
            {
                return new AppSettings();
            }
        }

        private void SaveSettings()
        {
            try
            {
                Directory.CreateDirectory(settingsDir);
                settings.Targets = targets.ToList();
                string file = Path.Combine(settingsDir, "settings.xml");
                string temp = file + ".tmp";
                using (var stream = File.Create(temp))
                    new XmlSerializer(typeof(AppSettings)).Serialize(stream, settings);
                if (File.Exists(file)) File.Replace(temp, file, null);
                else File.Move(temp, file);
            }
            catch (Exception ex)
            {
                statusLabel.Text = "Não foi possível salvar: " + ex.Message;
            }
        }

        private void SetStartup(bool enabled)
        {
            if (changingStartup) return;
            try
            {
                string arguments = enabled
                    ? "/Create /TN \"IPsec Watch\" /SC ONLOGON /TR \"\\\"" + Application.ExecutablePath + "\\\"\" /RL HIGHEST /F"
                    : "/Delete /TN \"IPsec Watch\" /F";
                RunSchtasks(arguments);
                settings.StartWithWindows = enabled;
                SaveSettings();
            }
            catch (Exception ex)
            {
                settings.StartWithWindows = false;
                changingStartup = true;
                startupCheck.Checked = false;
                changingStartup = false;
                MessageBox.Show(this, "Não foi possível configurar a inicialização: " + ex.Message,
                    "IPsec Watch", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private static void RunSchtasks(string arguments)
        {
            var start = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.Default
            };
            using (Process process = Process.Start(start))
            {
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit();
                if (process.ExitCode != 0)
                    throw new Exception(LastUsefulLine(String.IsNullOrWhiteSpace(error) ? output : error));
            }
        }

        private static void Normalize(MonitorTarget target)
        {
            if (String.IsNullOrWhiteSpace(target.Id)) target.Id = Guid.NewGuid().ToString("N");
            target.IntervalSeconds = Math.Max(5, target.IntervalSeconds);
            target.TimeoutMs = Math.Max(250, target.TimeoutMs);
            target.SourceAddress = FixedSourceAddress;
            if (String.IsNullOrWhiteSpace(target.ProbeType)) target.ProbeType = "TCP";
            if (target.TcpPort < 1 || target.TcpPort > 65535) target.TcpPort = 443;
        }
    }

    internal sealed class TargetDialog : Form
    {
        private readonly MonitorTarget target;
        private readonly TextBox name = new TextBox();
        private readonly TextBox host = new TextBox();
        private readonly TextBox peer = new TextBox();
        private readonly TextBox source = new TextBox();
        private readonly ComboBox probeType = new ComboBox();
        private readonly NumericUpDown tcpPort = new NumericUpDown();
        private readonly NumericUpDown interval = new NumericUpDown();
        private readonly NumericUpDown timeout = new NumericUpDown();
        private readonly CheckBox enabled = new CheckBox();

        public TargetDialog(MonitorTarget target)
        {
            this.target = target;
            Text = "Monitor de túnel";
            Icon = SystemIcons.Shield;
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ClientSize = new Size(500, 405);
            Font = new Font("Segoe UI", 9F);

            var table = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                Padding = new Padding(14),
                ColumnCount = 2,
                RowCount = 10
            };
            table.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 145));
            table.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            for (int i = 0; i < 9; i++) table.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
            table.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            name.Text = target.Name;
            host.Text = target.Host;
            peer.Text = target.PeerEndpoint;
            source.Text = "10.69.69.1";
            source.ReadOnly = true;
            source.BackColor = SystemColors.Control;
            probeType.DropDownStyle = ComboBoxStyle.DropDownList;
            probeType.Items.AddRange(new object[] { "TCP", "ICMP" });
            probeType.SelectedItem = String.Equals(target.ProbeType, "ICMP", StringComparison.OrdinalIgnoreCase) ? "ICMP" : "TCP";
            tcpPort.Minimum = 1; tcpPort.Maximum = 65535; tcpPort.Value = Math.Max(1, Math.Min(65535, target.TcpPort));
            probeType.SelectedIndexChanged += delegate { tcpPort.Enabled = probeType.Text == "TCP"; };
            tcpPort.Enabled = probeType.Text == "TCP";
            interval.Minimum = 5; interval.Maximum = 3600; interval.Value = Math.Max(5, Math.Min(3600, target.IntervalSeconds));
            timeout.Minimum = 250; timeout.Maximum = 30000; timeout.Increment = 250; timeout.Value = Math.Max(250, Math.Min(30000, target.TimeoutMs));
            enabled.Text = "Monitor habilitado"; enabled.Checked = target.Enabled; enabled.AutoSize = true;

            AddRow(table, 0, "Nome", name);
            AddRow(table, 1, "Host de keepalive *", host);
            AddRow(table, 2, "Tipo de teste", probeType);
            AddRow(table, 3, "Porta TCP", tcpPort);
            AddRow(table, 4, "IP de origem *", source);
            AddRow(table, 5, "Peer público (opcional)", peer);
            AddRow(table, 6, "Intervalo (segundos)", interval);
            AddRow(table, 7, "Timeout (ms)", timeout);
            table.Controls.Add(enabled, 1, 8);

            var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft };
            var ok = new Button { Text = "Salvar", DialogResult = DialogResult.None, Width = 90 };
            var cancel = new Button { Text = "Cancelar", DialogResult = DialogResult.Cancel, Width = 90 };
            ok.Click += SaveClick;
            buttons.Controls.Add(ok);
            buttons.Controls.Add(cancel);
            table.Controls.Add(buttons, 0, 9);
            table.SetColumnSpan(buttons, 2);
            Controls.Add(table);
            AcceptButton = ok;
            CancelButton = cancel;
        }

        private static void AddRow(TableLayoutPanel table, int row, string label, Control control)
        {
            var l = new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left };
            control.Dock = DockStyle.Fill;
            table.Controls.Add(l, 0, row);
            table.Controls.Add(control, 1, row);
        }

        private void SaveClick(object sender, EventArgs e)
        {
            if (String.IsNullOrWhiteSpace(name.Text) || String.IsNullOrWhiteSpace(host.Text))
            {
                MessageBox.Show(this, "Informe o nome, o host e um IP de origem válido.", "IPsec Watch",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            target.Name = name.Text.Trim();
            target.Host = host.Text.Trim();
            target.PeerEndpoint = peer.Text.Trim();
            target.SourceAddress = "10.69.69.1";
            target.ProbeType = probeType.Text;
            target.TcpPort = (int)tcpPort.Value;
            target.IntervalSeconds = (int)interval.Value;
            target.TimeoutMs = (int)timeout.Value;
            target.Enabled = enabled.Checked;
            DialogResult = DialogResult.OK;
            Close();
        }
    }
}
