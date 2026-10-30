'use client'

import Link from 'next/link'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { FolderGit2, Github, Plus } from 'lucide-react'
import { SeverityStrip } from '@/components/dashboard/most-vulnerable-repos'
import { Badge, Button, Card, CardBody, CardHeader, DemoBadge, EmptyState, ErrorState, Input, Label, Modal, Notice, PageHeader, Select, Skeleton, THead, Table, Td, Th, Tr } from '@/components/ui'
import { api, type Paged } from '@/lib/api'
import { ago, shortSha } from '@/lib/utils'

export default function RepositoriesPage() {
  const [open, setOpen] = useState(false)
  const repos = useQuery<Paged<any>>({ queryKey: ['repositories'], queryFn: () => api.get('/repositories?page_size=100') })
  return (
    <div>
      <PageHeader
        title="Repositories"
        description="Connected repositories, their scan history and security posture."
        actions={
          <Button onClick={() => setOpen(true)}>
            <Plus /> Connect repository
          </Button>
        }
      />
      {repos.error ? <ErrorState error={repos.error} /> : null}
      <Card>
        {repos.isLoading ? (
          <div className="space-y-2 p-4">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-12" />)}</div>
        ) : repos.data?.items.length ? (
          <Table>
            <THead>
              <tr>
                <Th>Repository</Th>
                <Th>Provider</Th>
                <Th>Ecosystems</Th>
                <Th>Open findings</Th>
                <Th>Score</Th>
                <Th>Last scan</Th>
              </tr>
            </THead>
            <tbody>
              {repos.data.items.map((r) => (
                <Tr key={r.id}>
                  <Td>
                    <Link href={`/repositories/${r.id}`} className="font-medium hover:text-primary">
                      {r.full_name}
                    </Link>{' '}
                    {r.is_demo && <DemoBadge />}
                    <p className="text-[11px] text-muted-foreground">
                      {r.default_branch} · {r.language || 'unknown language'}
                    </p>
                  </Td>
                  <Td>
                    <Badge>{r.provider}</Badge>
                  </Td>
                  <Td className="text-xs text-muted-foreground">{(r.ecosystems || []).join(', ') || '—'}</Td>
                  <Td className="w-48">
                    <p className="tabular mb-1 text-xs">{r.open_findings}</p>
                    <SeverityStrip counts={r.severity_counts} />
                  </Td>
                  <Td className="tabular">{r.security_score ?? '—'}</Td>
                  <Td className="text-xs text-muted-foreground">
                    {r.last_scanned_at ? (
                      <>
                        {ago(r.last_scanned_at)} <span className="font-mono">{shortSha(r.last_scanned_commit)}</span>
                      </>
                    ) : (
                      'never'
                    )}
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <Onboarding onConnect={() => setOpen(true)} />
        )}
      </Card>
      <ConnectModal open={open} onClose={() => setOpen(false)} />
    </div>
  )
}

function Onboarding({ onConnect }: { onConnect: () => void }) {
  return (
    <EmptyState
      icon={FolderGit2}
      title="No repositories connected"
      description={
        <ol className="mt-2 space-y-1 text-left">
          <li>1. Install the TRACE GitHub App on your account or org (or add a GitHub token in Settings).</li>
          <li>2. Connect a repository by owner/name, a public https clone URL, or the bundled test fixture.</li>
          <li>3. Trigger a scan — Trivy, OSV-Scanner, Semgrep and Gitleaks run on an isolated snapshot.</li>
        </ol>
      }
      action={<Button onClick={onConnect}>Connect repository</Button>}
    />
  )
}

function ConnectModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient()
  const [provider, setProvider] = useState('github')
  const [fullName, setFullName] = useState('')
  const [cloneUrl, setCloneUrl] = useState('')
  const [fixture, setFixture] = useState('')
  const [branch, setBranch] = useState('')
  const gh = useQuery({ queryKey: ['gh-available'], queryFn: () => api.get('/repositories/github/available'), enabled: open && provider === 'github' })
  const fixtures = useQuery<string[]>({ queryKey: ['fixtures'], queryFn: () => api.get('/repositories/fixtures'), enabled: open && provider === 'local' })
  const create = useMutation({
    mutationFn: (body: any) => api.post('/repositories', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['repositories'] })
      qc.invalidateQueries({ queryKey: ['gh-available'] })
      onClose()
    },
  })
  const submit = () =>
    create.mutate({
      provider,
      full_name: provider === 'github' ? fullName : undefined,
      clone_url: provider === 'git' ? cloneUrl : undefined,
      local_path: provider === 'local' ? fixture : undefined,
      default_branch: branch || undefined,
    })
  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Connect repository"
      wide
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} loading={create.isPending} disabled={(provider === 'github' && !fullName) || (provider === 'git' && !cloneUrl) || (provider === 'local' && !fixture)}>
            Connect
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div>
          <Label>Source</Label>
          <Select
            value={provider}
            onChange={setProvider}
            className="w-full"
            options={[
              { value: 'github', label: 'GitHub (App installation or token)' },
              { value: 'git', label: 'Public git repository (https)' },
              { value: 'local', label: 'Test fixture (demo mode)' },
            ]}
          />
        </div>
        {provider === 'github' && (
          <>
            <div>
              <Label hint="public repositories work without credentials">Repository</Label>
              <Input placeholder="owner/name or https://github.com/owner/name" value={fullName} onChange={(e) => setFullName(e.target.value)} />
            </div>
            <Card>
              <CardHeader title={<span className="inline-flex items-center gap-1.5"><Github className="h-4 w-4" /> Accessible repositories</span>} description="From GitHub App installations or the organization GitHub token" />
              <CardBody className="max-h-56 overflow-y-auto p-0">
                {gh.isLoading ? (
                  <Skeleton className="m-4 h-16" />
                ) : gh.data?.configured ? (
                  <ul className="divide-y text-sm">
                    {gh.data.repositories.map((r: any) => (
                      <li key={r.full_name} className="flex items-center justify-between px-4 py-2">
                        <span>
                          {r.full_name} {r.is_private && <Badge>private</Badge>}
                        </span>
                        {r.connected ? <Badge tone="success">connected</Badge> : <Button size="sm" variant="outline" onClick={() => setFullName(r.full_name)}>Select</Button>}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <div className="p-4">
                    <Notice>
                      {gh.data?.error || 'GitHub not configured.'} Add a GitHub token in Settings → Credentials, or configure GITHUB_APP_ID / GITHUB_APP_PRIVATE_KEY_PATH and install the app
                      {gh.data?.install_url && (
                        <>
                          {' '}
                          (<a className="text-primary underline" href={gh.data.install_url} target="_blank" rel="noreferrer">install</a>)
                        </>
                      )}
                      .
                    </Notice>
                  </div>
                )}
              </CardBody>
            </Card>
          </>
        )}
        {provider === 'git' && (
          <div>
            <Label>Clone URL</Label>
            <Input placeholder="https://gitlab.com/group/project.git" value={cloneUrl} onChange={(e) => setCloneUrl(e.target.value)} />
          </div>
        )}
        {provider === 'local' && (
          <div>
            <Label hint="intentionally vulnerable code for demos and tests">Fixture</Label>
            <Select value={fixture} onChange={setFixture} placeholder="Select fixture" className="w-full" options={(fixtures.data || []).map((f) => ({ value: f, label: f }))} />
          </div>
        )}
        {provider !== 'local' && (
          <div>
            <Label hint="defaults to the repository default branch">Branch</Label>
            <Input value={branch} onChange={(e) => setBranch(e.target.value)} placeholder="main" />
          </div>
        )}
        {create.error ? <ErrorState error={create.error} /> : null}
      </div>
    </Modal>
  )
}
