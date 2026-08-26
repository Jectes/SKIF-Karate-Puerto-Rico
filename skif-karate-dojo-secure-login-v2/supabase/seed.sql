-- Starter curriculum and portal reference data.
-- IMPORTANT: These are editable examples, not an official S.K.I.F. grading syllabus.
-- Replace requirement wording with the dojo's approved curriculum before production use.

begin;

insert into public.belt_ranks (name, level_order, color_hex, description, active)
values
  ('White Belt', 1, '#F5F5F5', 'Entry rank.', true),
  ('Yellow Belt', 2, '#F5D64E', 'Beginner progression.', true),
  ('Orange Belt', 3, '#F29A38', 'Beginner progression.', true),
  ('Green Belt', 4, '#4C9A61', 'Developing fundamentals.', true),
  ('Blue Belt', 5, '#3E70B8', 'Intermediate progression.', true),
  ('Purple Belt', 6, '#7750A5', 'Intermediate progression.', true),
  ('Brown Belt III', 7, '#7A4B2B', 'Advanced kyu progression.', true),
  ('Brown Belt II', 8, '#6B3F24', 'Advanced kyu progression.', true),
  ('Brown Belt I', 9, '#59321D', 'Senior kyu progression.', true),
  ('Black Belt', 10, '#151515', 'Dan-level progression.', true)
on conflict (name) do update set
  level_order = excluded.level_order,
  color_hex = excluded.color_hex,
  description = excluded.description,
  active = excluded.active;

-- Three neutral starter requirements per promotion target.
with starter(rank_name, category, title, description, sort_order) as (
  values
    ('Yellow Belt', 'kihon'::public.requirement_category, 'Fundamental techniques', 'Demonstrate the dojo-approved beginner stances, blocks, strikes, and kicks.', 10),
    ('Yellow Belt', 'kata'::public.requirement_category, 'Beginner kata', 'Perform the dojo-approved kata for this grading level.', 20),
    ('Yellow Belt', 'character'::public.requirement_category, 'Dojo etiquette', 'Demonstrate consistent etiquette, attention, and safe partner behavior.', 30),

    ('Orange Belt', 'kihon'::public.requirement_category, 'Developing fundamentals', 'Demonstrate the dojo-approved combinations with balance and control.', 10),
    ('Orange Belt', 'kata'::public.requirement_category, 'Required kata', 'Perform the dojo-approved kata for this grading level.', 20),
    ('Orange Belt', 'kumite'::public.requirement_category, 'Controlled partner work', 'Demonstrate safe distance, timing, and control in assigned partner drills.', 30),

    ('Green Belt', 'kihon'::public.requirement_category, 'Technique consistency', 'Maintain posture, focus, and consistent mechanics through assigned combinations.', 10),
    ('Green Belt', 'kata'::public.requirement_category, 'Required kata', 'Perform the dojo-approved kata for this grading level.', 20),
    ('Green Belt', 'attendance'::public.requirement_category, 'Training consistency', 'Meet the dojo-approved attendance and instructor-readiness standard.', 30),

    ('Blue Belt', 'kihon'::public.requirement_category, 'Intermediate combinations', 'Demonstrate the approved intermediate combinations with power and control.', 10),
    ('Blue Belt', 'kata'::public.requirement_category, 'Required kata', 'Perform the dojo-approved kata for this grading level.', 20),
    ('Blue Belt', 'kumite'::public.requirement_category, 'Intermediate partner work', 'Demonstrate controlled application, distance, and timing.', 30),

    ('Purple Belt', 'kihon'::public.requirement_category, 'Advanced fundamentals', 'Demonstrate efficient movement and consistent technique under instructor direction.', 10),
    ('Purple Belt', 'kata'::public.requirement_category, 'Required kata', 'Perform the dojo-approved kata for this grading level.', 20),
    ('Purple Belt', 'character'::public.requirement_category, 'Leadership habits', 'Model dojo etiquette and support less-experienced students appropriately.', 30),

    ('Brown Belt III', 'kihon'::public.requirement_category, 'Senior kyu fundamentals', 'Demonstrate the dojo-approved senior-kyu technical standard.', 10),
    ('Brown Belt III', 'kata'::public.requirement_category, 'Required kata', 'Perform the dojo-approved kata for this grading level.', 20),
    ('Brown Belt III', 'kumite'::public.requirement_category, 'Senior kyu partner work', 'Demonstrate mature control, timing, and tactical awareness.', 30),

    ('Brown Belt II', 'kihon'::public.requirement_category, 'Refined technique', 'Show repeatable mechanics, focus, and control across assigned techniques.', 10),
    ('Brown Belt II', 'kata'::public.requirement_category, 'Required kata', 'Perform the dojo-approved kata for this grading level.', 20),
    ('Brown Belt II', 'fitness'::public.requirement_category, 'Conditioning standard', 'Meet the dojo-approved age-appropriate conditioning standard.', 30),

    ('Brown Belt I', 'kihon'::public.requirement_category, 'Black-belt preparation', 'Demonstrate the dojo-approved pre-dan technical standard.', 10),
    ('Brown Belt I', 'kata'::public.requirement_category, 'Required kata', 'Perform the dojo-approved kata for this grading level.', 20),
    ('Brown Belt I', 'character'::public.requirement_category, 'Senior student conduct', 'Demonstrate reliability, humility, safety, and leadership.', 30),

    ('Black Belt', 'kihon'::public.requirement_category, 'Dan-level fundamentals', 'Demonstrate the official technical standard selected by the grading panel.', 10),
    ('Black Belt', 'kata'::public.requirement_category, 'Dan grading kata', 'Perform the official kata selection for the grading.', 20),
    ('Black Belt', 'kumite'::public.requirement_category, 'Dan-level application', 'Demonstrate the official partner-work and application standard.', 30)
)
insert into public.requirements (target_rank_id, category, title, description, sort_order, active)
select br.id, s.category, s.title, s.description, s.sort_order, true
from starter s
join public.belt_ranks br on br.name = s.rank_name
on conflict (target_rank_id, title) do update set
  category = excluded.category,
  description = excluded.description,
  sort_order = excluded.sort_order,
  active = excluded.active;

insert into public.class_groups (name, description, active)
values
  ('Children''s Karate', 'Age-appropriate Shotokan fundamentals and dojo etiquette.', true),
  ('Youth Fundamentals', 'Fundamentals, kata, controlled partner work, and physical development.', true),
  ('Teen & Adult Shotokan', 'Traditional Shotokan training for teen and adult students.', true),
  ('Advanced / Instructor Training', 'Advanced curriculum and instructor development.', true)
on conflict (name) do update set
  description = excluded.description,
  active = excluded.active;

insert into public.badges (name, description, icon, active)
values
  ('First Class', 'Completed the first recorded dojo class.', '🥋', true),
  ('Ten Classes', 'Completed ten recorded classes.', '🔟', true),
  ('Perfect Month', 'Met the dojo attendance goal for a full month.', '⭐', true),
  ('Kata Focus', 'Recognized for focused kata practice.', '🎯', true),
  ('Kumite Spirit', 'Recognized for controlled and respectful partner work.', '🤝', true),
  ('Leadership', 'Recognized for positive dojo leadership.', '🏅', true)
on conflict (name) do update set
  description = excluded.description,
  icon = excluded.icon,
  active = excluded.active;

insert into public.announcements (title, body, audience, published_at)
select
  'Welcome to the secure dojo portal',
  'Use this portal to review authorized schedules, attendance, progress, and dojo announcements. Contact the dojo if an account relationship is incorrect.',
  array['all']::text[],
  now()
where not exists (
  select 1 from public.announcements where title = 'Welcome to the secure dojo portal'
);

commit;
