'use client'

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Play, Plug, Plus, RefreshCw } from 'lucide-react'
import { useAuth } from '@/components/providers'
import { Badge, Button, Card, CardBody, CardHeader, Checkbox, CodeBlock, EmptyState, ErrorState, Input, Label, Modal, Notice, PageHeader, Pagination, Select, Skeleton, StatusBadge, Switch, THead, Table, Td, Textarea, Th, Tr } from '@/components/ui'
import { api, qs, type Paged } from '@/lib/api'
import { ago } from '@/lib/utils'

const AGENTS = ['vulnerability_research', 'code_analysis', 'risk_assessment', 'remediation', 'verification']

export default function MCPPage() {
  const qc = useQueryClient()
  const { role } = useAuth()
  const isAdmin = role === 'admin' || role === 'owner'
  const [addOpen, setAddOpen] = useState(false)
  const [exec, setExec] = useState<any>(null)
  const [page, setPage] = useState(1)
  const integrations = useQuery<any[]>({ queryKey: ['mcp'], queryFn: () => api.get('/mcp/integrations') })
  const logs = useQuery<Paged<any>>({ queryKey: ['mcp-logs', page], queryFn: () => api.get(`/mcp/executions${qs({ page })}`), refetchInterval: 10000 })
  const discover = useMutation({ mutationFn: (id: string) => api.post(`/mcp/integrations/${id}/discover`), onSettled: () => qc.invalidateQueries({ queryKey: ['mcp'] }) })
  const updateTool = useMutation({ mutationFn: ({ id, body }: { id: string; body: any }) => api.patch(`/mcp/tools/${id}`, body), onSuccess: () => qc.invalidateQueries({ queryKey: ['mcp'] }) })
  const toggle = useMutation({ mutationFn: ({ id, active }: { id: string; active: boolean }) => api.patch(`/mcp/integrations/${id}`, { is_active: active }), onSuccess: () => qc.invalidateQueries({ queryKey: ['mcp'] }) })
  return (
    <div>
      <PageHeader
        title="MCP integrations"
        description="Model Context Protocol servers whose tools agents may invoke — default-deny allowlist, per-agent permissions, approval for sensitive tools."
        actions={isAdmin && <Button onClick={() => setAddOpen(true)}><Plus /> Add server</Button>}
      />
      {(discover.error || updateTool.error) && <ErrorState error={discover.error || updateTool.error} className="mb-4" />}
      <div className="space-y-4">
        {integrations.isLoading && <Skeleton className="h-64" />}
        {integrations.data?.map((i) => (
          <Card key={i.id}>
            <CardHeader
              title={<span className="flex items-center gap-2"><Plug className="h-4 w-4" /> {i.name} {i.is_builtin && <Badge tone="primary">built-in</Badge>} <Badge>{i.transport}</Badge> <StatusBadge status={i.status} /></span>}
              description={<>{i.description} {i.status_detail && <span className="block text-[11px]">{i.status_detail}{i.last_connected_at ? ` · ${ago(i.last_connected_at)}` : ''}</span>}</>}
              action={isAdmin && (
                <div className="flex items-center gap-3">
                  <span className="flex items-center gap-2 text-xs text-muted-foreground">Active <Switch checked={i.is_active} onChange={(v) => toggle.mutate({ id: i.id, active: v })} label="Integration active" /></span>
                  <Button size="sm" variant="outline" onClick={() => discover.mutate(i.id)} loading={discover.isPending && discover.variables === i.id}><RefreshCw /> Discover tools</Button>
                </div>
              )}
            />
            {i.tools.length ? (
              <Table>
                <THead><tr><Th>Tool</Th><Th>Sensitivity</Th><Th>Allowed</Th><Th>Approval</Th><Th>Agents permitted</Th><Th /></tr></THead>
                <tbody>
                  {i.tools.map((t: any) => (
                    <Tr key={t.id}>
                      <Td className="max-w-[340px]">
                        <p className="font-mono text-xs font-medium">{t.name}</p>
                        <p className="line-clamp-2 text-[11px] text-muted-foreground">{t.description}</p>
                      </Td>
                      <Td><Badge tone={t.sensitivity === 'write' ? 'danger' : t.sensitivity === 'network' ? 'warning' : 'neutral'}>{t.sensitivity}</Badge></Td>
                      <Td><Switch checked={t.is_allowed} disabled={!isAdmin} onChange={(v) => updateTool.mutate({ id: t.id, body: { is_allowed: v } })} label={`Allow ${t.name}`} /></Td>
                      <Td><Switch checked={t.requires_approval} disabled={!isAdmin} onChange={(v) => updateTool.mutate({ id: t.id, body: { requires_approval: v } })} label={`Require approval for ${t.name}`} /></Td>
                      <Td>
                        <div className="flex max-w-[320px] flex-wrap gap-1">
                          {AGENTS.map((a) => {
                            const on = (t.allowed_agents || []).includes(a)
                            return (
                              <button key={a} disabled={!isAdmin} onClick={() => updateTool.mutate({ id: t.id, body: { allowed_agents: on ? t.allowed_agents.filter((x: string) => x !== a) : [...(t.allowed_agents || []), a] } })}
                                className={`rounded px-1.5 py-0.5 text-[10px] ring-1 ring-inset ${on ? 'bg-primary/10 text-primary ring-primary/30' : 'text-muted-foreground ring-border hover:bg-accent'}`} aria-pressed={on}>
                                {a.replace('_', ' ')}
                              </button>
                            )
                          })}
                        </div>
                      </Td>
                      <Td>{isAdmin && t.sensitivity !== 'read' && <Button size="sm" variant="ghost" onClick={() => setExec(t)}><Play /> Run</Button>}</Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            ) : <EmptyState title="No tools discovered" description="Run discovery to connect to the server and list its tools." />}
          </Card>
        ))}
        <Card>
          <CardHeader title="Tool execution log" description="All MCP calls by agents and users, including denials" />
          {logs.data?.items.length ? (
            <>
              <Table>
                <THead><tr><Th>Time</Th><Th>Tool</Th><Th>Invoked by</Th><Th>Status</Th><Th>Duration</Th><Th>Detail</Th></tr></THead>
                <tbody>
                  {logs.data.items.map((e) => (
                    <Tr key={e.id}>
                      <Td className="whitespace-nowrap text-xs">{ago(e.created_at)}</Td>
                      <Td className="font-mono text-xs">{e.tool_name}</Td>
                      <Td className="font-mono text-xs">{e.invoked_by}</Td>
                      <Td><StatusBadge status={e.status} /></Td>
                      <Td className="tabular text-xs">{e.duration_ms ?? '—'} ms</Td>
                      <Td className="max-w-[360px] truncate font-mono text-[11px] text-muted-foreground" title={e.error_message || e.result_preview}>{e.error_message || e.result_preview}</Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
              <Pagination page={logs.data.page} pages={logs.data.pages} total={logs.data.total} onPage={setPage} />
            </>
          ) : <EmptyState title="No tool executions yet" />}
        </Card>
      </div>
      <AddServer open={addOpen} onClose={() => setAddOpen(false)} />
      {exec && <ExecuteTool tool={exec} onClose={() => setExec(null)} />}
    </div>
  )
}

function AddServer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient()
  const [mode, setMode] = useState('template')
  const [template, setTemplate] = useState('')
  const [name, setName] = useState('')
  const [url, setUrl] = useState('')
  const reg = useQuery<any[]>({ queryKey: ['mcp-registry'], queryFn: () => api.get('/mcp/registry'), enabled: open })
  const m = useMutation({ mutationFn: () => api.post('/mcp/integrations', mode === 'template' ? { name: template, template } : { name, url }), onSuccess: () => { qc.invalidateQueries({ queryKey: ['mcp'] }); onClose() } })
  return (
    <Modal open={open} onClose={onClose} title="Add MCP server" footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button onClick={() => m.mutate()} loading={m.isPending} disabled={mode === 'template' ? !template : !name || !url}>Add</Button></>}>
      <div className="space-y-3">
        <Select value={mode} onChange={setMode} className="w-full" options={[{ value: 'template', label: 'From allowlisted registry' }, { value: 'remote', label: 'Remote server (streamable HTTP)' }]} />
        {mode === 'template' ? (
          <div>
            <Label>Server</Label>
            <Select value={template} onChange={setTemplate} placeholder="Select" className="w-full" options={(reg.data || []).map((r) => ({ value: r.name, label: `${r.name}${r.requires_credential ? ` (needs ${r.requires_credential})` : ''}` }))} />
            {template && <p className="mt-2 text-xs text-muted-foreground">{reg.data?.find((r) => r.name === template)?.description}</p>}
          </div>
        ) : (
          <>
            <div><Label>Name</Label><Input value={name} onChange={(e) => setName(e.target.value)} /></div>
            <div><Label>URL</Label><Input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://mcp.example.com/mcp" /></div>
          </>
        )}
        <Notice>Arbitrary local commands cannot be registered. Newly discovered tools are denied until explicitly allowed and require approval by default.</Notice>
        {m.error ? <ErrorState error={m.error} /> : null}
      </div>
    </Modal>
  )
}

function ExecuteTool({ tool, onClose }: { tool: any; onClose: () => void }) {
  const qc = useQueryClient()
  const props = tool.input_schema?.properties || {}
  const [args, setArgs] = useState(JSON.stringify(Object.fromEntries(Object.keys(props).map((k) => [k, props[k].default ?? ''])), null, 2))
  const [approved, setApproved] = useState(false)
  const m = useMutation({ mutationFn: () => api.post(`/mcp/tools/${tool.id}/execute`, { arguments: JSON.parse(args), approved }), onSettled: () => qc.invalidateQueries({ queryKey: ['mcp-logs'] }) })
  return (
    <Modal open onClose={onClose} title={`Execute ${tool.name}`} wide footer={<><Button variant="outline" onClick={onClose}>Close</Button><Button onClick={() => m.mutate()} loading={m.isPending}><Play /> Execute</Button></>}>
      <div className="space-y-3">
        <p className="text-xs text-muted-foreground">{tool.description}</p>
        <div><Label>Arguments (JSON)</Label><Textarea value={args} onChange={(e) => setArgs(e.target.value)} className="min-h-[120px] font-mono text-xs" /></div>
        {tool.requires_approval && <Checkbox checked={approved} onChange={setApproved} label="I explicitly approve this sensitive tool call (recorded in the audit log)" />}
        {m.error ? <ErrorState error={m.error} /> : null}
        {m.data && <CodeBlock code={JSON.stringify(m.data, null, 2)} className="max-h-80" />}
      </div>
    </Modal>
  )
}
